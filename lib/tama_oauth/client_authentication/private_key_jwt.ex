defmodule TamaOAuth.ClientAuthentication.PrivateKeyJWT do
  @moduledoc "Validates RFC 7523 private-key JWT client authentication."

  alias TamaOAuth.{ClientMetadata, Crypto, Error, JWKS, JWT}

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @max_assertion_bytes 16_384
  @max_kid_bytes 128

  @spec authenticate(map(), keyword()) :: {:ok, String.t()} | {:error, Error.t()}
  def authenticate(context, opts) when is_map(context) and is_list(opts) do
    with :ok <- validate_context(context),
         assertion when is_binary(assertion) <- context.params["client_assertion"],
         true <-
           byte_size(assertion) in 1..Keyword.get(
             opts,
             :max_assertion_bytes,
             @max_assertion_bytes
           ),
         {:ok, algorithm, kid} <- validate_header(assertion, context.metadata, opts),
         {:ok, key} <- resolve_key(context.metadata, kid, algorithm, opts),
         {:ok, claims} <- verify(assertion, key, algorithm),
         :ok <- validate_claims(claims, context.client_id, opts),
         :ok <- claim_replay(context.client_id, claims["jti"], claims["exp"], opts) do
      {:ok, context.client_id}
    else
      {:error, %Error{} = error} -> {:error, error}
      false -> invalid_client(:assertion_header)
      _ -> invalid_client(:assertion_header)
    end
  end

  def authenticate(_context, _opts), do: invalid_client(:method_detection)

  defp validate_context(%{
         client_id: client_id,
         metadata: %ClientMetadata{} = metadata,
         params: params,
         authorization_headers: []
       })
       when is_binary(client_id) and is_map(params) do
    valid? =
      client_id == metadata.client_id and
        "private_key_jwt" in metadata.token_endpoint_auth_methods_supported and
        params["client_assertion_type"] == @assertion_type and
        not Map.has_key?(params, "client_secret")

    if valid?, do: :ok, else: invalid_client(:method_detection)
  end

  defp validate_context(_context), do: invalid_client(:method_detection)

  defp validate_header(assertion, metadata, opts) do
    allowed = Keyword.get(opts, :algorithms, ["RS256"])

    with {:ok, %{"alg" => algorithm, "kid" => kid}} <- JWT.peek_header(assertion),
         true <- algorithm in allowed,
         true <- algorithm in metadata.token_endpoint_auth_signing_algorithms,
         true <- is_binary(kid) and byte_size(kid) in 1..@max_kid_bytes do
      {:ok, algorithm, kid}
    else
      _ -> invalid_client(:assertion_header)
    end
  end

  defp resolve_key(metadata, kid, algorithm, opts) do
    case Keyword.fetch(opts, :key_resolver) do
      {:ok, resolver} when is_function(resolver, 3) ->
        case resolver.(metadata, kid, algorithm) do
          {:ok, key} when is_map(key) -> validate_resolved_key(key, kid, algorithm, opts)
          {:error, :temporarily_unavailable} -> temporarily_unavailable(:jwks_fetch)
          _ -> invalid_client(:jwks_key_selection)
        end

      _ ->
        temporarily_unavailable(:jwks_fetch)
    end
  end

  defp validate_resolved_key(key, kid, algorithm, opts) do
    allowed = Keyword.get(opts, :algorithms, ["RS256"])

    case JWKS.select(%{"keys" => [key]}, kid, algorithm, algorithms: allowed) do
      {:ok, selected} -> {:ok, selected}
      _ -> invalid_client(:jwks_key_selection)
    end
  end

  defp verify(assertion, key, algorithm) do
    case JWT.verify_signature(assertion, key, algorithm) do
      {:ok, claims} -> {:ok, claims}
      _ -> invalid_client(:assertion_signature)
    end
  end

  defp validate_claims(claims, client_id, opts) when is_map(claims) do
    token_endpoint = Keyword.fetch!(opts, :token_endpoint)
    now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now() |> DateTime.to_unix() end)
    skew = Keyword.get(opts, :clock_skew_seconds, 30)
    max_lifetime = Keyword.get(opts, :max_lifetime_seconds, 300)
    issued_at = claims["iat"]
    expires_at = claims["exp"]
    not_before = Map.get(claims, "nbf", issued_at)

    valid? =
      claims["iss"] == client_id and claims["sub"] == client_id and
        is_binary(claims["jti"]) and byte_size(claims["jti"]) in 1..256 and
        valid_audience?(claims["aud"], token_endpoint) and
        valid_times?(issued_at, expires_at, not_before, now, skew, max_lifetime)

    if valid?, do: :ok, else: invalid_client(:assertion_claims)
  end

  defp valid_audience?(audience, expected) when is_binary(audience), do: audience == expected

  defp valid_audience?(audience, expected) when is_list(audience),
    do: audience != [] and Enum.all?(audience, &is_binary/1) and expected in audience

  defp valid_audience?(_audience, _expected), do: false

  defp valid_times?(issued_at, expires_at, not_before, now, skew, max_lifetime) do
    Enum.all?([issued_at, expires_at, not_before, now, skew, max_lifetime], &is_integer/1) and
      issued_at <= now + skew and not_before <= now + skew and expires_at > now - skew and
      expires_at > issued_at and issued_at >= now - max_lifetime - skew and
      expires_at - issued_at <= max_lifetime
  end

  defp claim_replay(client_id, assertion_id, expires_at, opts) do
    with claimer when is_function(claimer, 2) <- Keyword.get(opts, :claim_replay),
         {:ok, expires_at} <-
           DateTime.from_unix(expires_at + Keyword.get(opts, :clock_skew_seconds, 30)) do
      digest = Crypto.digest(client_id <> <<0>> <> assertion_id)

      case claimer.(digest, expires_at) do
        :ok -> :ok
        {:error, :replayed} -> invalid_client(:assertion_replay)
        _ -> temporarily_unavailable(:assertion_replay)
      end
    else
      _ -> temporarily_unavailable(:assertion_replay)
    end
  end

  defp invalid_client(stage), do: {:error, Error.new(:invalid_client, stage: stage)}

  defp temporarily_unavailable(stage),
    do: {:error, Error.new(:temporarily_unavailable, stage: stage)}
end
