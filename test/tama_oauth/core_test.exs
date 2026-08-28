defmodule TamaOAuth.CoreTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{AuthorizationRequest, Crypto, Error, PKCE, Scope, TokenRequest}
  alias TamaOAuth.URI, as: OAuthURI

  @verifier "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
  @challenge "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
  @resource "https://tama.example/mcp/app"

  test "starts the library task supervisor" do
    assert Process.whereis(TamaOAuth.TaskSupervisor)
  end

  test "constructs bounded protocol errors without exposing internal details" do
    error =
      Error.new(:invalid_client,
        description: "Client authentication failed",
        stage: :signature,
        details: %{kid: "private"}
      )

    assert error.status == 401

    assert Error.to_map(error) == %{
             "error" => "invalid_client",
             "error_description" => "Client authentication failed"
           }

    refute inspect(Error.to_map(error)) =~ "private"
  end

  test "creates opaque credentials and compares digests safely" do
    token = Crypto.opaque_token(4, fn 4 -> <<0, 1, 2, 3>> end)
    digest = Crypto.digest(token)

    assert token == "AAECAw"
    assert Crypto.matches_digest?(token, digest)
    refute Crypto.matches_digest?(token <> "x", digest)
    refute Crypto.secure_compare(<<1>>, <<1, 0>>)
  end

  test "implements the RFC 7636 S256 vector" do
    assert {:ok, @challenge} = PKCE.challenge(@verifier)
    assert PKCE.verify(@verifier, @challenge)
    refute PKCE.verify(String.duplicate("a", 42), @challenge)
    refute PKCE.valid_verifier?("contains spaces" <> String.duplicate("a", 40))
  end

  test "normalizes scopes in server catalogue order" do
    assert {:ok, "mcp.read mcp.message"} =
             Scope.normalize("mcp.message mcp.read mcp.message", [
               "mcp.read",
               "mcp.message"
             ])

    assert {:error, %Error{code: :invalid_scope}} =
             Scope.normalize("mcp.admin", ["mcp.message"])

    assert {:error, %Error{code: :invalid_scope}} =
             Scope.normalize("mcp.read\nmcp.message", ["mcp.read", "mcp.message"])
  end

  test "matches redirects exactly except for native loopback ephemeral ports" do
    assert OAuthURI.redirect_allowed?(
             "http://127.0.0.1:43123/callback?source=codex",
             ["http://127.0.0.1/callback?source=codex"]
           )

    refute OAuthURI.redirect_allowed?(
             "http://127.0.0.1:43123/other?source=codex",
             ["http://127.0.0.1/callback?source=codex"]
           )

    refute OAuthURI.redirect_allowed?(
             "http://localhost:43123/callback?source=codex",
             ["http://127.0.0.1/callback?source=codex"]
           )

    refute OAuthURI.redirect_allowed?(
             "http://127.0.0.1:43124/callback",
             ["http://127.0.0.1:43123/callback"]
           )
  end

  test "contains scoped CIMD client IDs without accepting nested or query paths" do
    prefix = "https://chatgpt.com/oauth/codex/"

    assert OAuthURI.scoped_client_id?(
             "https://chatgpt.com/oauth/codex/AwfF3DmIiHl5/client.json",
             prefix
           )

    refute OAuthURI.scoped_client_id?(
             "https://chatgpt.com/oauth/codex/AwfF3DmIiHl5/nested/client.json",
             prefix
           )

    refute OAuthURI.scoped_client_id?(
             "https://chatgpt.com/oauth/codex/AwfF3DmIiHl5/client.json?redirect=evil",
             prefix
           )
  end

  test "builds path-specific protected resource metadata URLs" do
    assert {:ok, "https://tama.example/.well-known/oauth-protected-resource/mcp/app"} =
             OAuthURI.protected_resource_metadata_uri(@resource)
  end

  test "validates an exact authorization request" do
    assert {:ok, request} =
             AuthorizationRequest.validate(valid_authorization_params(),
               resource: @resource,
               supported_scopes: ["mcp.message"]
             )

    assert request.resource == @resource
    assert request.scope == "mcp.message"

    assert {:error, %Error{code: :invalid_target}} =
             AuthorizationRequest.validate(
               Map.put(valid_authorization_params(), "resource", "https://evil.example"),
               resource: @resource,
               supported_scopes: ["mcp.message"]
             )
  end

  test "parses token grants and detects the presented client authentication method" do
    code_params = %{
      "grant_type" => "authorization_code",
      "client_id" => "https://client.example/client.json",
      "code" => "code",
      "redirect_uri" => "https://client.example/callback",
      "code_verifier" => @verifier
    }

    assert {:ok, %TokenRequest{authentication_method: :none}} = TokenRequest.parse(code_params)

    assert {:error, %Error{code: :invalid_request, stage: :authorization_code}} =
             code_params
             |> Map.put("code_verifier", String.duplicate("a", 42))
             |> TokenRequest.parse()

    private_params =
      Map.merge(code_params, %{
        "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion" => "header.payload.signature"
      })

    assert {:ok, %TokenRequest{authentication_method: :private_key_jwt}} =
             TokenRequest.parse(private_params)

    assert {:error, %Error{code: :invalid_client}} =
             TokenRequest.parse(Map.put(code_params, "client_secret", "forbidden"))
  end

  defp valid_authorization_params do
    %{
      "response_type" => "code",
      "client_id" => "https://client.example/client.json",
      "redirect_uri" => "https://client.example/callback",
      "resource" => @resource,
      "scope" => "mcp.message",
      "state" => "opaque-state",
      "code_challenge" => @challenge,
      "code_challenge_method" => "S256"
    }
  end
end
