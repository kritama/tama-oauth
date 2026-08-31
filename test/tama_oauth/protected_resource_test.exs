defmodule TamaOAuth.ProtectedResourceTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{Error, JWT, ProtectedResource}

  @now 1_787_900_000

  setup_all do
    private_jwk = JOSE.JWK.generate_key({:rsa, 2_048})
    {_fields, private_key} = JOSE.JWK.to_map(private_jwk)
    {_fields, public_key} = private_jwk |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()

    public_key =
      Map.merge(public_key, %{"kid" => "memovee-signing-key", "alg" => "RS256", "use" => "sig"})

    claims = %{
      "iss" => "https://memovee.example",
      "sub" => "actor-identifier",
      "aud" => "https://tama.example/mcp/app",
      "client_id" => "https://client.example/client.json",
      "scope" => "mcp.message",
      "jti" => "access-token-reference"
    }

    {:ok, token, claims} =
      JWT.mint_access_token(claims, private_key,
        algorithm: "RS256",
        kid: "memovee-signing-key",
        now: @now,
        ttl: 300
      )

    active =
      claims
      |> Map.put("active", true)
      |> Map.put("grant_id", "grant-identifier")

    %{
      active: active,
      claims: claims,
      private_key: private_key,
      public_key: public_key,
      token: token
    }
  end

  test "verifies, introspects, agrees, and returns canonical claims", context do
    test_pid = self()

    resolver = fn kid, algorithm ->
      send(test_pid, {:resolved, kid, algorithm})
      {:ok, context.public_key}
    end

    introspector = fn token, offline_claims ->
      send(test_pid, {:introspected, token, offline_claims})
      {:ok, context.active}
    end

    assert {:ok, claims} =
             ProtectedResource.authenticate(
               context.token,
               options(resolver, introspector)
             )

    assert claims ==
             context.claims
             |> Map.take(ProtectedResource.agreement_fields())
             |> Map.put("grant_id", context.active["grant_id"])

    assert_receive {:resolved, "memovee-signing-key", "RS256"}
    assert_receive {:introspected, token, offline_claims}
    assert token == context.token
    assert offline_claims == context.claims
  end

  test "rejects every offline and online claim mismatch", context do
    mismatches = [
      {"iss", "https://other.example"},
      {"sub", "other-actor"},
      {"aud", "https://other.example/mcp/app"},
      {"client_id", "https://other.example/client.json"},
      {"scope", "mcp.message mcp.message"},
      {"jti", "other-token-reference"},
      {"iat", @now - 1},
      {"exp", @now + 299}
    ]

    for {field, value} <- mismatches do
      introspector = fn _token, _claims -> {:ok, Map.put(context.active, field, value)} end

      assert {:error, %Error{code: :invalid_token, stage: :claim_agreement}} =
               ProtectedResource.authenticate(
                 context.token,
                 options(key_resolver(context), introspector)
               )
    end
  end

  test "rejects inactive tokens and preserves package introspection errors", context do
    inactive = fn _token, _claims -> {:ok, :inactive} end

    assert {:error, %Error{code: :invalid_token, stage: :introspection}} =
             ProtectedResource.authenticate(
               context.token,
               options(key_resolver(context), inactive)
             )

    unavailable = Error.new(:temporarily_unavailable, stage: :introspection_timeout)
    failed = fn _token, _claims -> {:error, unavailable} end

    assert {:error, ^unavailable} =
             ProtectedResource.authenticate(
               context.token,
               options(key_resolver(context), failed)
             )
  end

  test "rejects an active response without a grant identifier", context do
    invalid = fn _token, _claims -> {:ok, Map.delete(context.active, "grant_id")} end

    assert {:error, %Error{code: :invalid_token, stage: :introspection}} =
             ProtectedResource.authenticate(
               context.token,
               options(key_resolver(context), invalid)
             )
  end

  test "classifies verification-key failures without introspecting", context do
    test_pid = self()
    introspector = fn _token, _claims -> send(test_pid, :introspected) end
    unavailable = fn _kid, _algorithm -> {:error, :temporarily_unavailable} end

    assert {:error, %Error{code: :temporarily_unavailable, stage: :verification_key}} =
             ProtectedResource.authenticate(
               context.token,
               options(unavailable, introspector)
             )

    refute_receive :introspected
  end

  test "rejects bounded token-header violations before resolving a key", context do
    test_pid = self()

    resolver = fn kid, algorithm ->
      send(test_pid, {:resolved, kid, algorithm})
      {:error, :temporarily_unavailable}
    end

    introspector = fn _token, _claims ->
      send(test_pid, :introspected)
      {:ok, context.active}
    end

    malformed_tokens = [
      context.token <> String.duplicate("x", 16_385),
      token_with_kid(context, 123),
      token_with_kid(context, String.duplicate("k", 129))
    ]

    for token <- malformed_tokens do
      assert {:error, %Error{code: :invalid_token, stage: :access_token}} =
               ProtectedResource.authenticate(token, options(resolver, introspector))
    end

    refute_receive {:resolved, _kid, _algorithm}
    refute_receive :introspected
  end

  test "fails closed when an application callback raises", context do
    resolver = fn _kid, _algorithm -> raise "key store failure" end
    introspector = fn _token, _claims -> {:ok, context.active} end

    assert {:error, %Error{code: :invalid_token, stage: :protected_resource}} =
             ProtectedResource.authenticate(context.token, options(resolver, introspector))
  end

  test "requires complete trusted application configuration", context do
    opts = options(key_resolver(context), fn _token, _claims -> {:ok, context.active} end)

    for field <- [:issuer, :audience, :scopes, :key_resolver, :introspector] do
      assert {:error, %Error{code: :invalid_request, stage: :protected_resource}} =
               ProtectedResource.authenticate(context.token, Keyword.delete(opts, field))
    end
  end

  defp options(key_resolver, introspector) do
    [
      issuer: "https://memovee.example",
      audience: "https://tama.example/mcp/app",
      scopes: ["mcp.message"],
      algorithms: ["RS256"],
      now: @now,
      clock_skew_seconds: 30,
      key_resolver: key_resolver,
      introspector: introspector
    ]
  end

  defp key_resolver(context), do: fn _kid, _algorithm -> {:ok, context.public_key} end

  defp token_with_kid(context, kid) do
    signer = Joken.Signer.create("RS256", context.private_key, %{"kid" => kid})
    {:ok, token} = Joken.Signer.sign(context.claims, signer)
    token
  end
end
