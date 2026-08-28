defmodule TamaOAuth.ClientAuthenticationTest do
  use ExUnit.Case, async: true

  alias TamaOAuth.{ClientAuthentication, ClientMetadata, Error}

  @client_id "https://client.example/oauth/client.json"
  @token_endpoint "https://memovee.example/auth/tokens"
  @now 1_787_900_000

  setup_all do
    private_jwk = JOSE.JWK.generate_key({:rsa, 2_048})
    {_fields, private_key} = JOSE.JWK.to_map(private_jwk)
    {_fields, public_key} = JOSE.JWK.to_public_map(private_jwk)

    public_key = Map.merge(public_key, %{"kid" => "client-key", "alg" => "RS256", "use" => "sig"})

    document = %{
      "client_id" => @client_id,
      "client_name" => "Example client",
      "redirect_uris" => ["https://client.example/callback"],
      "grant_types" => ["authorization_code", "refresh_token"],
      "response_types" => ["code"],
      "token_endpoint_auth_methods_supported" => ["none", "private_key_jwt"],
      "token_endpoint_auth_signing_alg_values_supported" => ["RS256"],
      "jwks_uri" => "https://client.example/oauth/jwks.json"
    }

    {:ok, metadata} = ClientMetadata.validate(document, @client_id)

    %{private_key: private_key, public_key: public_key, metadata: metadata}
  end

  test "authenticates a public client and rejects mixed credentials", context do
    public_context = %{
      client_id: @client_id,
      metadata: context.metadata,
      params: %{},
      authorization_headers: []
    }

    assert {:ok, @client_id} = ClientAuthentication.authenticate(:none, public_context)

    assert {:error, %Error{code: :invalid_client}} =
             ClientAuthentication.authenticate(
               :none,
               put_in(public_context.params, %{"client_secret" => "forbidden"})
             )
  end

  test "authenticates private_key_jwt and rejects assertion replay", context do
    assertion = assertion(context.private_key)
    replay_store = start_supervised!({Agent, fn -> MapSet.new() end})

    claim_replay = fn digest, _expires_at ->
      Agent.get_and_update(replay_store, fn claimed ->
        if MapSet.member?(claimed, digest) do
          {{:error, :replayed}, claimed}
        else
          {:ok, MapSet.put(claimed, digest)}
        end
      end)
    end

    opts = private_opts(context.public_key, claim_replay)

    assert {:ok, @client_id} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, assertion),
               opts
             )

    assert {:error, %Error{code: :invalid_client, stage: :assertion_replay}} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, assertion),
               opts
             )
  end

  test "rejects wrong audience, signature, and algorithm", context do
    accept_replay = fn _digest, _expires_at -> :ok end
    opts = private_opts(context.public_key, accept_replay)

    wrong_audience = assertion(context.private_key, %{"aud" => "https://evil.example/token"})

    assert {:error, %Error{stage: :assertion_claims}} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, wrong_audience),
               opts
             )

    missing_assertion_id = assertion(context.private_key, %{"jti" => nil})

    assert {:error, %Error{stage: :assertion_claims}} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, missing_assertion_id),
               opts
             )

    other_private = JOSE.JWK.generate_key({:rsa, 2_048}) |> JOSE.JWK.to_map() |> elem(1)
    wrong_signature = assertion(other_private)

    assert {:error, %Error{stage: :assertion_signature}} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, wrong_signature),
               opts
             )

    unsupported = assertion(context.private_key, %{}, "PS256")

    assert {:error, %Error{stage: :assertion_header}} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, unsupported),
               opts
             )
  end

  test "fails closed when key or replay persistence is unavailable", context do
    assertion = assertion(context.private_key)

    assert {:error, %Error{code: :temporarily_unavailable, stage: :jwks_fetch}} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, assertion),
               token_endpoint: @token_endpoint,
               now: @now,
               key_resolver: fn _metadata, _kid, _algorithm ->
                 {:error, :temporarily_unavailable}
               end,
               claim_replay: fn _digest, _expires_at -> :ok end
             )

    assert {:error, %Error{code: :temporarily_unavailable, stage: :assertion_replay}} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, assertion),
               private_opts(context.public_key, fn _digest, _expires_at ->
                 {:error, :unavailable}
               end)
             )
  end

  test "independently rejects an ineligible key returned by the resolver", context do
    assertion = assertion(context.private_key)
    weak_jwk = JOSE.JWK.generate_key({:rsa, 1_024})
    {_fields, weak_key} = JOSE.JWK.to_public_map(weak_jwk)

    weak_key =
      Map.merge(weak_key, %{"kid" => "client-key", "alg" => "RS256", "use" => "sig"})

    opts =
      private_opts(weak_key, fn _digest, _expires_at ->
        flunk("replay storage must not be reached for an ineligible key")
      end)

    assert {:error, %Error{code: :invalid_client, stage: :jwks_key_selection}} =
             ClientAuthentication.authenticate(
               :private_key_jwt,
               private_context(context, assertion),
               opts
             )
  end

  defp private_context(context, assertion) do
    %{
      client_id: @client_id,
      metadata: context.metadata,
      params: %{
        "client_assertion_type" => "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion" => assertion
      },
      authorization_headers: []
    }
  end

  defp private_opts(public_key, claim_replay) do
    [
      token_endpoint: @token_endpoint,
      now: @now,
      algorithms: ["RS256"],
      key_resolver: fn _metadata, "client-key", "RS256" -> {:ok, public_key} end,
      claim_replay: claim_replay
    ]
  end

  defp assertion(private_key, overrides \\ %{}, algorithm \\ "RS256") do
    claims =
      Map.merge(
        %{
          "iss" => @client_id,
          "sub" => @client_id,
          "aud" => @token_endpoint,
          "jti" => "assertion-#{System.unique_integer([:positive])}",
          "iat" => @now,
          "exp" => @now + 120
        },
        overrides
      )

    {:ok, token} =
      Joken.Signer.sign(
        claims,
        Joken.Signer.create(algorithm, private_key, %{"kid" => "client-key"})
      )

    token
  end
end
