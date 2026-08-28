defmodule TamaOAuth.JWTJWKSTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{Error, JWKS, JWT}

  @now 1_787_900_000

  setup_all do
    private_jwk = JOSE.JWK.generate_key({:rsa, 2_048})
    {_fields, private_key} = JOSE.JWK.to_map(private_jwk)
    {_fields, public_key} = JOSE.JWK.to_public_map(private_jwk)

    public_key =
      Map.merge(public_key, %{"kid" => "signing-key", "alg" => "RS256", "use" => "sig"})

    private_key =
      Map.merge(private_key, %{"kid" => "signing-key", "alg" => "RS256", "use" => "sig"})

    %{private_key: private_key, public_key: public_key, jwks: %{"keys" => [public_key]}}
  end

  test "validates and selects eligible verification keys", %{public_key: public_key, jwks: jwks} do
    assert {:ok, set} = JWKS.validate(jwks)
    assert {:ok, ^public_key} = JWKS.select(set, "signing-key", "RS256")
    assert {:error, :unknown_kid} = JWKS.select(set, "unknown", "RS256")
    assert {:error, :ineligible_jwk} = JWKS.select(set, "signing-key", "ES256")

    assert {:error, :invalid_jwks} =
             JWKS.validate(%{"keys" => [public_key, public_key]})
  end

  test "publishes public-only key material", %{private_key: private_key} do
    assert {:ok, %{"keys" => [public]}} = JWKS.public_document([private_key])
    assert public["kid"] == "signing-key"

    for parameter <- ~w(d p q dp dq qi oth k) do
      refute Map.has_key?(public, parameter)
    end
  end

  test "never publishes symmetric key material" do
    symmetric = %{
      "kty" => "oct",
      "kid" => "symmetric",
      "use" => "sig",
      "k" => Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    }

    assert {:error, :invalid_jwks} = JWKS.public_document([symmetric])
  end

  test "rejects weak RSA keys", %{public_key: public_key} do
    weak_jwk = JOSE.JWK.generate_key({:rsa, 1_024})
    {_fields, weak} = JOSE.JWK.to_public_map(weak_jwk)
    weak = Map.merge(weak, %{"kid" => "weak", "alg" => "RS256", "use" => "sig"})

    assert {:ok, set} = JWKS.validate(%{"keys" => [weak, public_key]})
    assert {:error, :ineligible_jwk} = JWKS.select(set, "weak", "RS256")
  end

  test "mints and verifies an audience-bound access token", context do
    claims = access_claims()

    assert {:ok, token, signed_claims} =
             JWT.mint_access_token(claims, context.private_key,
               algorithm: "RS256",
               kid: "signing-key",
               now: @now,
               ttl: 600
             )

    assert signed_claims["exp"] == @now + 600

    assert {:ok, verified} =
             JWT.verify_access_token(token, context.jwks,
               issuer: claims.iss,
               audience: claims.aud,
               scopes: ["mcp.message"],
               now: @now
             )

    assert verified["sub"] == claims.sub

    assert {:error, %Error{code: :invalid_token}} =
             JWT.verify_access_token(token, context.jwks,
               issuer: claims.iss,
               audience: "https://other.example/mcp",
               scopes: ["mcp.message"],
               now: @now
             )
  end

  test "rejects expired, tampered, and unknown-key tokens", context do
    claims = access_claims()

    {:ok, token, _claims} =
      JWT.mint_access_token(claims, context.private_key,
        algorithm: "RS256",
        kid: "signing-key",
        now: @now,
        ttl: 60
      )

    verification_opts = [
      issuer: claims.iss,
      audience: claims.aud,
      scopes: ["mcp.message"],
      now: @now + 100,
      clock_skew_seconds: 0
    ]

    assert {:error, %Error{code: :invalid_token}} =
             JWT.verify_access_token(token, context.jwks, verification_opts)

    [header, payload, signature] = String.split(token, ".")
    tampered = Enum.join([header, payload <> "A", signature], ".")

    assert {:error, %Error{code: :invalid_token}} =
             JWT.verify_access_token(tampered, context.jwks, verification_opts)

    {_fields, other_public} =
      {:rsa, 2_048}
      |> JOSE.JWK.generate_key()
      |> JOSE.JWK.to_public_map()

    other_jwks = %{"keys" => [Map.put(other_public, "kid", "other")]}

    assert {:error, %Error{code: :invalid_token}} =
             JWT.verify_access_token(token, other_jwks, verification_opts)
  end

  defp access_claims do
    %{
      iss: "https://memovee.example",
      sub: "019c0000-0000-7000-8000-000000000001",
      aud: "https://tama.example/mcp/app",
      client_id: "https://client.example/client.json",
      scope: "mcp.message",
      jti: "019c0000-0000-7000-8000-000000000002"
    }
  end
end
