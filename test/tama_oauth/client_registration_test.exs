defmodule TamaOAuth.ClientRegistrationTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{ClientRegistration, Error}

  @valid %{
    "application_type" => "native",
    "redirect_uris" => ["http://127.0.0.1:19876/mcp/oauth/callback"],
    "client_name" => "OpenCode",
    "client_uri" => "https://opencode.ai",
    "grant_types" => ["authorization_code", "refresh_token"],
    "response_types" => ["code"],
    "token_endpoint_auth_method" => "none",
    "scope" => "mcp.message"
  }

  test "normalizes a native public client and produces a stable digest" do
    assert {:ok, first} =
             ClientRegistration.normalize(@valid, supported_scopes: ["mcp.message"])

    reordered = %{
      @valid
      | "redirect_uris" => [
          "http://localhost:19877/second",
          "http://127.0.0.1:19876/mcp/oauth/callback"
        ],
        "grant_types" => ["refresh_token", "authorization_code"]
    }

    reversed = %{reordered | "redirect_uris" => Enum.reverse(reordered["redirect_uris"])}

    assert {:ok, second} =
             ClientRegistration.normalize(reordered, supported_scopes: ["mcp.message"])

    assert {:ok, third} =
             ClientRegistration.normalize(reversed, supported_scopes: ["mcp.message"])

    assert byte_size(first.metadata_digest) == 32
    assert second.metadata_digest == third.metadata_digest
  end

  test "supports HTTPS callbacks for web clients" do
    params = %{
      @valid
      | "application_type" => "web",
        "redirect_uris" => ["https://app.example/callback"]
    }

    assert {:ok, registration} =
             ClientRegistration.normalize(params, supported_scopes: ["mcp.message"])

    assert registration.application_type == "web"
  end

  test "rejects unsafe native callbacks and confidential methods" do
    for redirect <- [
          "http://example.com:19876/callback",
          "https://127.0.0.1:19876/callback",
          "http://127.0.0.1/callback",
          "http://127.0.0.1:80/callback",
          "http://user@127.0.0.1:19876/callback",
          "http://127.0.0.1:19876/callback#fragment"
        ] do
      assert {:error, %Error{code: :invalid_redirect_uri, stage: :redirect_uris}} =
               ClientRegistration.normalize(
                 %{@valid | "redirect_uris" => [redirect]},
                 supported_scopes: ["mcp.message"]
               )
    end

    assert {:error, %Error{code: :invalid_client_metadata, stage: :authentication_method}} =
             ClientRegistration.normalize(
               %{@valid | "token_endpoint_auth_method" => "client_secret_post"},
               supported_scopes: ["mcp.message"]
             )
  end

  test "requires the 2026 MCP application type and supported scopes" do
    assert {:error, %Error{code: :invalid_client_metadata, stage: :application_type}} =
             ClientRegistration.normalize(
               Map.delete(@valid, "application_type"),
               supported_scopes: ["mcp.message"]
             )

    assert {:error, %Error{code: :invalid_scope}} =
             ClientRegistration.normalize(
               %{@valid | "scope" => "mcp.admin"},
               supported_scopes: ["mcp.message"]
             )
  end
end
