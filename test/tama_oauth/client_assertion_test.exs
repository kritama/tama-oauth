defmodule TamaOAuth.ClientAssertionTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{ClientAssertion, ClientAuthentication, ClientMetadata, Error}

  @client_id "tama-mcp-app"
  @audience "https://memovee.example/auth/introspections"
  @now 1_787_900_000

  setup_all do
    private_jwk = JOSE.JWK.generate_key({:rsa, 2_048})
    {_fields, private_key} = JOSE.JWK.to_map(private_jwk)
    {_fields, public_key} = JOSE.JWK.to_public_map(private_jwk)

    private_key =
      Map.merge(private_key, %{"kid" => "tama-introspection", "alg" => "RS256", "use" => "sig"})

    public_key =
      Map.merge(public_key, %{"kid" => "tama-introspection", "alg" => "RS256", "use" => "sig"})

    metadata = %ClientMetadata{
      client_id: @client_id,
      client_name: "Tama MCP App",
      redirect_uris: [],
      grant_types: [],
      response_types: [],
      token_endpoint_auth_methods_supported: ["private_key_jwt"],
      token_endpoint_auth_signing_algorithms: ["RS256"],
      jwks_uri: "https://tama.example/.well-known/jwks.json"
    }

    %{private_key: private_key, public_key: public_key, metadata: metadata}
  end

  test "mints the exact private_key_jwt assertion accepted by the verifier", context do
    assert {:ok, assertion, claims} = mint(context.private_key)

    assert ClientAssertion.assertion_type() ==
             "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

    assert {:ok, %{"alg" => "RS256", "kid" => "tama-introspection"}} =
             Joken.peek_header(assertion)

    assert claims == %{
             "iss" => @client_id,
             "sub" => @client_id,
             "aud" => @audience,
             "jti" => "assertion-id",
             "iat" => @now,
             "exp" => @now + 60
           }

    assert {:ok, @client_id} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               %{
                 client_id: @client_id,
                 metadata: context.metadata,
                 params: %{
                   "client_assertion_type" => ClientAssertion.assertion_type(),
                   "client_assertion" => assertion
                 },
                 authorization_headers: []
               },
               token_endpoint: @audience,
               now: @now,
               algorithms: ["RS256"],
               key_resolver: fn _metadata, "tama-introspection", "RS256" ->
                 {:ok, context.public_key}
               end,
               claim_replay: fn _digest, _expires_at -> :ok end
             )
  end

  test "rejects invalid claims, intervals, headers, and output bounds", context do
    invalid_cases = [
      {"", @audience, [jti: "assertion-id"]},
      {@client_id, "not-a-uri", [jti: "assertion-id"]},
      {@client_id, @audience, [jti: ""]},
      {@client_id, @audience, [jti: "assertion-id", now: -1]},
      {@client_id, @audience, [jti: "assertion-id", ttl: 301]},
      {@client_id, @audience, [jti: "assertion-id", algorithm: "HS256"]},
      {@client_id, @audience, [jti: "assertion-id", kid: ""]},
      {@client_id, @audience, [jti: "assertion-id", max_assertion_bytes: 1]}
    ]

    for {client_id, audience, overrides} <- invalid_cases do
      assert {:error, %Error{code: :invalid_request}} =
               ClientAssertion.mint(
                 client_id,
                 audience,
                 context.private_key,
                 Keyword.merge(mint_options(), overrides)
               )
    end
  end

  test "preserves valid noncanonical audience spellings", context do
    audiences = [
      "https://memovee.example:443/auth/introspections",
      "https://MEMOVEE.EXAMPLE/auth/introspections"
    ]

    for audience <- audiences do
      assert {:ok, _assertion, %{"aud" => ^audience}} =
               ClientAssertion.mint(
                 @client_id,
                 audience,
                 context.private_key,
                 mint_options()
               )
    end
  end

  test "rejects public, symmetric, weak, and mismatched signing keys", context do
    symmetric = %{
      "kty" => "oct",
      "k" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    }

    weak = JOSE.JWK.generate_key({:rsa, 1_024}) |> JOSE.JWK.to_map() |> elem(1)
    mismatched = Map.put(context.private_key, "kid", "another-key")

    for key <- [context.public_key, symmetric, weak, mismatched] do
      assert {:error, %Error{code: :invalid_request, stage: :client_assertion_key}} =
               ClientAssertion.mint(@client_id, @audience, key, mint_options())
    end
  end

  defp mint(private_key) do
    ClientAssertion.mint(@client_id, @audience, private_key, mint_options())
  end

  defp mint_options do
    [
      algorithm: "RS256",
      algorithms: ["RS256"],
      kid: "tama-introspection",
      jti: "assertion-id",
      now: @now,
      ttl: 60,
      max_lifetime_seconds: 300
    ]
  end
end
