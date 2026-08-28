defmodule TamaOAuth.LifecycleMetadataTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{Error, Introspection, RefreshToken, Revocation}
  alias TamaOAuth.Metadata.{AuthorizationServer, ProtectedResource}

  @now ~U[2026-08-28 00:00:00Z]

  test "returns an explicit refresh rotation decision" do
    state = refresh_state()

    assert {:ok, decision} =
             RefreshToken.evaluate(state, @now, idle_lifetime_seconds: 3_600)

    assert decision.family_id == "family"
    assert decision.invalidate_token_id == "refresh-1"
    assert decision.next_generation == 2
  end

  test "detects family replay and rejects expired credentials" do
    assert {:replay, "family"} =
             RefreshToken.evaluate(%{refresh_state() | status: :rotated}, @now, [])

    assert {:error, %Error{code: :invalid_grant, stage: :refresh_expired}} =
             RefreshToken.evaluate(
               %{refresh_state() | expires_at: DateTime.add(@now, -1, :second)},
               @now,
               []
             )

    assert {:error, %Error{stage: :refresh_idle_expired}} =
             RefreshToken.evaluate(
               %{refresh_state() | last_used_at: DateTime.add(@now, -3_601, :second)},
               @now,
               idle_lifetime_seconds: 3_600
             )
  end

  test "builds active and inactive introspection responses" do
    claims = access_claims()

    assert {:ok, response} = Introspection.active(claims, "grant-id")
    assert response["active"]
    assert response["grant_id"] == "grant-id"
    assert Introspection.inactive() == %{"active" => false}

    assert {:ok, ^response} =
             Introspection.validate_response(response,
               issuer: claims["iss"],
               audience: claims["aud"],
               scopes: ["mcp.message"],
               now: claims["iat"]
             )

    assert {:ok, :inactive} = Introspection.validate_response(Introspection.inactive(), [])
  end

  test "rejects wrongly bound introspection responses" do
    {:ok, response} = Introspection.active(access_claims(), "grant-id")

    assert {:error, %Error{code: :invalid_token}} =
             Introspection.validate_response(response,
               issuer: response["iss"],
               audience: "https://other.example/mcp",
               scopes: ["mcp.message"],
               now: response["iat"]
             )

    assert {:error, %Error{code: :invalid_token, stage: :introspection_claims}} =
             access_claims()
             |> Map.put("sub", nil)
             |> Introspection.active("grant-id")
  end

  test "parses bounded introspection and revocation requests" do
    assert {:ok, "token"} = Introspection.parse_request(%{"token" => "token"})

    assert {:ok, revocation} =
             Revocation.parse(%{
               "token" => "token",
               "client_id" => "client",
               "token_type_hint" => "refresh_token"
             })

    assert revocation.token_type_hint == "refresh_token"
    assert Revocation.response() == :ok

    assert {:error, %Error{code: :invalid_request}} =
             Revocation.parse(%{
               "token" => "token",
               "client_id" => "client",
               "token_type_hint" => "other"
             })
  end

  test "builds authorization-server and protected-resource metadata" do
    assert {:ok, authorization_metadata} =
             AuthorizationServer.build(
               issuer: "https://memovee.example",
               authorization_endpoint: "https://memovee.example/auth/authorizations/new",
               token_endpoint: "https://memovee.example/auth/tokens",
               jwks_uri: "https://memovee.example/.well-known/jwks.json",
               revocation_endpoint: "https://memovee.example/auth/revocations",
               introspection_endpoint: "https://memovee.example/auth/introspections",
               protected_resources: ["https://tama.example/mcp/app"],
               scopes_supported: ["mcp.message"],
               token_endpoint_auth_methods_supported: ["none", "private_key_jwt"],
               token_endpoint_auth_signing_alg_values_supported: ["RS256"]
             )

    assert authorization_metadata["code_challenge_methods_supported"] == ["S256"]
    assert authorization_metadata["authorization_response_iss_parameter_supported"]
    assert authorization_metadata["protected_resources"] == ["https://tama.example/mcp/app"]

    assert {:ok, protected_metadata} =
             ProtectedResource.build(
               resource: "https://tama.example/mcp/app",
               authorization_servers: ["https://memovee.example"],
               scopes_supported: ["mcp.message"]
             )

    assert protected_metadata["bearer_methods_supported"] == ["header"]

    assert {:error, :invalid_metadata} =
             AuthorizationServer.build(
               issuer: "https://memovee.example",
               authorization_endpoint: "https://memovee.example/auth/authorizations/new",
               token_endpoint: "https://memovee.example/auth/tokens",
               jwks_uri: "https://memovee.example/.well-known/jwks.json",
               revocation_endpoint: "not a URL",
               scopes_supported: ["mcp.message"],
               token_endpoint_auth_methods_supported: ["none"]
             )
  end

  defp refresh_state do
    %RefreshToken.State{
      id: "refresh-1",
      family_id: "family",
      generation: 1,
      status: :active,
      issued_at: DateTime.add(@now, -600, :second),
      expires_at: DateTime.add(@now, 86_400, :second),
      last_used_at: DateTime.add(@now, -60, :second)
    }
  end

  defp access_claims do
    now = DateTime.to_unix(@now)

    %{
      "iss" => "https://memovee.example",
      "sub" => "019c0000-0000-7000-8000-000000000001",
      "aud" => "https://tama.example/mcp/app",
      "client_id" => "https://client.example/client.json",
      "scope" => "mcp.message",
      "jti" => "019c0000-0000-7000-8000-000000000002",
      "iat" => now,
      "exp" => now + 600
    }
  end
end
