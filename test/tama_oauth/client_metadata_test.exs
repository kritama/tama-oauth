defmodule TamaOAuth.ClientMetadataTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{ClientMetadata, Crypto}

  defmodule Fetcher do
    @behaviour TamaOAuth.ClientMetadata.Fetcher

    @impl true
    def fetch(url, opts) do
      assert opts[:origin] == url
      document = Keyword.fetch!(opts, :document)
      body = Jason.encode!(document)

      {:ok, %{body: body, document: document, url: url, cache_ttl: 300}}
    end
  end

  @client_id "https://client.example/oauth/client.json"

  test "normalizes a public CIMD document" do
    assert {:ok, metadata} = ClientMetadata.validate(public_document(), @client_id)
    assert metadata.client_id == @client_id
    assert metadata.token_endpoint_auth_methods_supported == ["none"]
    assert metadata.token_endpoint_auth_signing_algorithms == []
    assert metadata.jwks_uri == nil
    assert ClientMetadata.redirect_allowed?("https://client.example/callback", metadata)
  end

  test "normalizes private key JWT metadata and requires a same-origin JWKS" do
    document =
      public_document()
      |> Map.put("token_endpoint_auth_methods_supported", ["none", "private_key_jwt"])
      |> Map.put("token_endpoint_auth_signing_alg_values_supported", ["RS256"])
      |> Map.put("jwks_uri", "https://client.example/oauth/jwks.json")

    assert {:ok, metadata} = ClientMetadata.validate(document, @client_id)
    assert metadata.jwks_uri == "https://client.example/oauth/jwks.json"

    assert {:error, :invalid_client_metadata} =
             ClientMetadata.validate(
               Map.put(document, "jwks_uri", "https://keys.evil.example/jwks.json"),
               @client_id
             )
  end

  test "rejects identity changes, symmetric credentials, and invalid redirects" do
    assert {:error, :invalid_client_metadata} =
             ClientMetadata.validate(
               Map.put(public_document(), "client_id", "https://other.example/client.json"),
               @client_id
             )

    assert {:error, :invalid_client_metadata} =
             ClientMetadata.validate(
               Map.put(public_document(), "client_secret", "secret"),
               @client_id
             )

    assert {:error, :invalid_client_metadata} =
             ClientMetadata.validate(
               Map.put(public_document(), "redirect_uris", ["https://client.example/cb#fragment"]),
               @client_id
             )
  end

  test "fetch binds the digest and cache metadata to the exact response" do
    document = public_document()

    assert {:ok, metadata} =
             ClientMetadata.fetch(@client_id,
               fetcher: Fetcher,
               fetch_options: [document: document]
             )

    assert metadata.metadata_digest == Crypto.digest(Jason.encode!(document))
    assert metadata.validated_url == @client_id
    assert metadata.cache_ttl == 300
  end

  test "requires HTTPS client IDs except for an explicit local test policy" do
    local_id = "http://127.0.0.1:4000/client.json"
    document = %{public_document() | "client_id" => local_id}

    refute ClientMetadata.valid_client_id_url?(local_id)
    assert ClientMetadata.valid_client_id_url?(local_id, allow_local?: true)
    assert {:ok, _metadata} = ClientMetadata.validate(document, local_id, allow_local?: true)
  end

  defp public_document do
    %{
      "client_id" => @client_id,
      "client_name" => "Example client",
      "client_uri" => "https://client.example/",
      "redirect_uris" => ["https://client.example/callback", "http://127.0.0.1/callback"],
      "grant_types" => ["authorization_code", "refresh_token"],
      "response_types" => ["code"],
      "token_endpoint_auth_method" => "none"
    }
  end
end
