defmodule TamaOAuth.ProtectedResource do
  @moduledoc """
  Authenticates an access token at an OAuth protected resource.

  The application supplies trusted policy values plus callbacks for verification
  key resolution and active token introspection. This module owns the protocol
  sequence: it verifies the JWT, requires an active introspection response,
  compares every security-relevant claim exactly, and returns one canonical
  claim set.

  Key caching, private-key custody, rate limiting, telemetry, application
  identities, and principal construction remain application-owned concerns.
  The introspector receives the verified offline claims so an application can
  apply policy such as a pre-introspection rate limit before making the remote
  request.
  """

  alias TamaOAuth.{Error, Introspection, JWT}

  @agreement_fields ~w(iss sub aud client_id scope jti iat exp)
  @supported_algorithms ["RS256", "PS256", "ES256"]

  @type key_resolver ::
          (String.t(), String.t() ->
             {:ok, map()}
             | {:error, Error.t() | atom()})

  @type introspector ::
          (String.t(), map() ->
             {:ok, map() | :inactive}
             | {:error, Error.t() | atom()})

  @spec authenticate(String.t(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def authenticate(token, opts) when is_binary(token) and is_list(opts) do
    with {:ok, context} <- context(opts),
         {:ok, offline_claims} <- verify(token, context),
         {:ok, online_claims} <- introspect(token, offline_claims, context),
         :ok <- agree(offline_claims, online_claims),
         {:ok, validated_claims} <- validate_introspection_claims(online_claims, context) do
      {:ok, canonical_claims(offline_claims, validated_claims)}
    end
  rescue
    _error -> invalid_token(:protected_resource)
  catch
    _kind, _reason -> invalid_token(:protected_resource)
  end

  def authenticate(_token, _opts), do: invalid_request(:protected_resource)

  @doc "Returns the claims that must agree between JWT verification and introspection."
  @spec agreement_fields() :: [String.t()]
  def agreement_fields, do: @agreement_fields

  defp context(opts) do
    context = %{
      issuer: Keyword.get(opts, :issuer),
      audience: Keyword.get(opts, :audience),
      scopes: Keyword.get(opts, :scopes),
      algorithms: Keyword.get(opts, :algorithms, ["RS256"]),
      now: Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now() |> DateTime.to_unix() end),
      clock_skew_seconds: Keyword.get(opts, :clock_skew_seconds, 30),
      key_resolver: Keyword.get(opts, :key_resolver),
      introspector: Keyword.get(opts, :introspector)
    }

    if valid_context?(context),
      do: {:ok, context},
      else: invalid_request(:protected_resource)
  end

  defp valid_context?(context) do
    valid_bindings?(context) and valid_scopes?(context.scopes) and
      valid_algorithms?(context.algorithms) and valid_time?(context) and
      valid_callbacks?(context)
  end

  defp valid_bindings?(context),
    do: nonempty_string?(context.issuer) and nonempty_string?(context.audience)

  defp valid_scopes?(scopes),
    do: is_list(scopes) and scopes != [] and Enum.all?(scopes, &nonempty_string?/1)

  defp valid_algorithms?(algorithms) do
    is_list(algorithms) and algorithms != [] and
      length(algorithms) == length(Enum.uniq(algorithms)) and
      Enum.all?(algorithms, &(&1 in @supported_algorithms))
  end

  defp valid_time?(context) do
    is_integer(context.now) and context.now >= 0 and
      is_integer(context.clock_skew_seconds) and context.clock_skew_seconds in 0..300
  end

  defp valid_callbacks?(context),
    do: is_function(context.key_resolver, 2) and is_function(context.introspector, 2)

  defp verify(token, context) do
    with {:ok, %{"alg" => algorithm, "kid" => kid}} <- JWT.peek_header(token),
         true <- algorithm in context.algorithms,
         {:ok, key} <- resolve_key(context.key_resolver, kid, algorithm),
         {:ok, claims} <-
           JWT.verify_access_token(token, %{"keys" => [key]},
             algorithms: context.algorithms,
             issuer: context.issuer,
             audience: context.audience,
             scopes: context.scopes,
             now: context.now,
             clock_skew_seconds: context.clock_skew_seconds
           ) do
      {:ok, claims}
    else
      {:error, %Error{} = error} -> {:error, error}
      _error -> invalid_token(:access_token)
    end
  end

  defp resolve_key(resolver, kid, algorithm) do
    case resolver.(kid, algorithm) do
      {:ok, key} when is_map(key) -> {:ok, key}
      {:error, %Error{} = error} -> {:error, error}
      {:error, :temporarily_unavailable} -> temporarily_unavailable(:verification_key)
      _error -> invalid_token(:verification_key)
    end
  end

  defp introspect(token, offline_claims, context) do
    case context.introspector.(token, offline_claims) do
      {:ok, :inactive} ->
        invalid_token(:introspection, :inactive)

      {:ok, claims} when is_map(claims) ->
        {:ok, claims}

      {:error, %Error{} = error} ->
        {:error, error}

      {:error, :temporarily_unavailable} ->
        temporarily_unavailable(:introspection)

      _error ->
        invalid_token(:introspection, :invalid_response)
    end
  end

  defp validate_introspection_claims(claims, context) do
    case Introspection.validate_response(claims,
           issuer: context.issuer,
           audience: context.audience,
           scopes: context.scopes,
           now: context.now,
           clock_skew_seconds: context.clock_skew_seconds
         ) do
      {:ok, validated_claims} when is_map(validated_claims) -> {:ok, validated_claims}
      {:ok, :inactive} -> invalid_token(:introspection, :inactive)
      {:error, %Error{}} -> invalid_token(:introspection, :invalid_response)
    end
  end

  defp agree(offline_claims, online_claims) do
    if Map.take(offline_claims, @agreement_fields) ==
         Map.take(online_claims, @agreement_fields),
       do: :ok,
       else: invalid_token(:claim_agreement, :claim_mismatch)
  end

  defp canonical_claims(offline_claims, online_claims) do
    offline_claims
    |> Map.take(@agreement_fields)
    |> Map.put("grant_id", online_claims["grant_id"])
  end

  defp nonempty_string?(value), do: is_binary(value) and String.trim(value) != ""

  defp invalid_request(stage), do: {:error, Error.new(:invalid_request, stage: stage)}

  defp invalid_token(stage, reason \\ nil) do
    details = if reason, do: %{reason: reason}, else: %{}
    {:error, Error.new(:invalid_token, stage: stage, details: details)}
  end

  defp temporarily_unavailable(stage),
    do: {:error, Error.new(:temporarily_unavailable, stage: stage)}
end
