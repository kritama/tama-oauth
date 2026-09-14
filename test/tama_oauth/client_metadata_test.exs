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

  defmodule RecordingFetcher do
    @behaviour TamaOAuth.ClientMetadata.Fetcher

    @impl true
    def fetch(url, opts) do
      document = Keyword.fetch!(opts, :document)
      send(self(), {:fetcher_allow_local, Keyword.get(opts, :allow_local?)})

      {:ok, %{body: Jason.encode!(document), document: document, url: url, cache_ttl: 300}}
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
    assert ClientMetadata.valid_client_id_url?(local_id, allow_local_metadata_fetch?: true)

    assert {:ok, _metadata} =
             ClientMetadata.validate(document, local_id, allow_local_metadata_fetch?: true)
  end

  @codex_client_id "https://chatgpt.com/oauth/codex/client.json"
  @production [allow_local_metadata_fetch?: false, allow_loopback_redirects?: true]

  test "fetches a public Codex CIMD with loopback redirects while local metadata fetch is disabled" do
    opts =
      [fetcher: RecordingFetcher, fetch_options: [document: codex_document()]] ++ @production

    assert {:ok, metadata} = ClientMetadata.fetch(@codex_client_id, opts)

    assert metadata.client_name == "Codex"
    assert metadata.redirect_uris == ["http://127.0.0.1/callback", "http://localhost/callback"]
    assert_receive {:fetcher_allow_local, false}
  end

  test "nested fetch options cannot override the top-level metadata fetch policy" do
    opts =
      [
        fetcher: RecordingFetcher,
        fetch_options: [document: codex_document(), allow_local?: true],
        allow_local_metadata_fetch?: false,
        allow_loopback_redirects?: true
      ]

    assert {:ok, _metadata} = ClientMetadata.fetch(@codex_client_id, opts)
    assert_receive {:fetcher_allow_local, false}
  end

  test "allows a localhost loopback redirect under the native client policy" do
    document = %{codex_document() | "redirect_uris" => ["http://localhost/callback"]}

    assert {:ok, metadata} =
             ClientMetadata.validate(document, @codex_client_id, @production)

    assert metadata.redirect_uris == ["http://localhost/callback"]
  end

  test "rejects a loopback redirect when allow_loopback_redirects? is disabled" do
    document = %{codex_document() | "redirect_uris" => ["http://127.0.0.1/callback"]}

    assert {:error, :invalid_client_metadata} =
             ClientMetadata.validate(document, @codex_client_id,
               allow_local_metadata_fetch?: false,
               allow_loopback_redirects?: false
             )
  end

  test "rejects an HTTP redirect to a non-loopback host" do
    document = %{public_document() | "redirect_uris" => ["http://callback.example/callback"]}

    assert {:error, :invalid_client_metadata} =
             ClientMetadata.validate(document, @client_id, @production)
  end

  test "rejects a local client identifier URL under production options" do
    local_id = "http://127.0.0.1:4000/client.json"
    document = %{public_document() | "client_id" => local_id}

    assert {:error, :invalid_client_metadata} =
             ClientMetadata.validate(document, local_id, @production)
  end

  test "enabling loopback redirects does not enable a local client identifier URL" do
    local_id = "http://127.0.0.1:4000/client.json"

    refute ClientMetadata.valid_client_id_url?(local_id, allow_loopback_redirects?: true)
  end

  test "enabling loopback redirects does not permit a local jwks_uri" do
    document =
      public_document()
      |> Map.put("token_endpoint_auth_methods_supported", ["none", "private_key_jwt"])
      |> Map.put("token_endpoint_auth_signing_alg_values_supported", ["RS256"])
      |> Map.put("jwks_uri", "http://127.0.0.1/jwks.json")

    assert {:error, :invalid_client_metadata} =
             ClientMetadata.validate(document, @client_id, @production)
  end

  test "matches a loopback callback with an ephemeral port per the existing contract" do
    document = %{public_document() | "redirect_uris" => ["http://127.0.0.1/callback"]}

    assert {:ok, metadata} =
             ClientMetadata.validate(document, @client_id, @production)

    assert ClientMetadata.redirect_allowed?("http://127.0.0.1/callback", metadata)
    assert ClientMetadata.redirect_allowed?("http://127.0.0.1:53713/callback", metadata)

    refute ClientMetadata.redirect_allowed?("http://127.0.0.1:53713/other", metadata)
    refute ClientMetadata.redirect_allowed?("http://localhost:53713/callback", metadata)
    refute ClientMetadata.redirect_allowed?("https://127.0.0.1:53713/callback", metadata)
    refute ClientMetadata.redirect_allowed?("http://127.0.0.1:53713/callback?state=1", metadata)
    refute ClientMetadata.redirect_allowed?("http://127.0.0.1:53713/callback#fragment", metadata)
    refute ClientMetadata.redirect_allowed?("http://user@127.0.0.1:53713/callback", metadata)
  end

  test "does not apply ephemeral loopback matching to an explicitly ported redirect" do
    document = %{public_document() | "redirect_uris" => ["http://127.0.0.1:4000/callback"]}

    assert {:ok, metadata} =
             ClientMetadata.validate(document, @client_id, @production)

    assert ClientMetadata.redirect_allowed?("http://127.0.0.1:4000/callback", metadata)
    refute ClientMetadata.redirect_allowed?("http://127.0.0.1:53713/callback", metadata)
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

  defp codex_document do
    %{
      "client_id" => @codex_client_id,
      "client_name" => "Codex",
      "application_type" => "native",
      "redirect_uris" => ["http://127.0.0.1/callback", "http://localhost/callback"],
      "token_endpoint_auth_method" => "none",
      "grant_types" => ["authorization_code", "refresh_token"],
      "response_types" => ["code"]
    }
  end
end
