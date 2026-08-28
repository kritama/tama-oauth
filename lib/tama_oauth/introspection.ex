defmodule TamaOAuth.Introspection do
  @moduledoc "Builds and validates RFC 7662-style token introspection values."

  alias TamaOAuth.{Error, Scope}

  @max_token_bytes 16_384

  @spec parse_request(map(), keyword()) :: {:ok, String.t()} | {:error, Error.t()}
  def parse_request(params, opts \\ [])

  def parse_request(%{"token" => token}, opts) do
    max_bytes = Keyword.get(opts, :max_token_bytes, @max_token_bytes)

    if is_binary(token) and byte_size(token) in 1..max_bytes,
      do: {:ok, token},
      else: {:error, Error.new(:invalid_request, stage: :introspection_request)}
  end

  def parse_request(_params, _opts),
    do: {:error, Error.new(:invalid_request, stage: :introspection_request)}

  @spec inactive() :: map()
  def inactive, do: %{"active" => false}

  @spec active(map(), String.t()) :: {:ok, map()} | {:error, Error.t()}
  def active(claims, grant_id) when is_map(claims) and is_binary(grant_id) do
    required = ~w(iss sub aud client_id scope jti iat exp)

    if valid_active_claims?(claims) do
      {:ok,
       claims
       |> Map.take(required)
       |> Map.put("grant_id", grant_id)
       |> Map.put("active", true)}
    else
      {:error, Error.new(:invalid_token, stage: :introspection_claims)}
    end
  end

  def active(_claims, _grant_id),
    do: {:error, Error.new(:invalid_token, stage: :introspection_claims)}

  @spec validate_response(map(), keyword()) ::
          {:ok, map() | :inactive} | {:error, Error.t()}
  def validate_response(%{"active" => false}, _opts), do: {:ok, :inactive}

  def validate_response(%{"active" => true} = response, opts) do
    issuer = Keyword.fetch!(opts, :issuer)
    audience = Keyword.fetch!(opts, :audience)
    scopes = Keyword.fetch!(opts, :scopes)
    now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now() |> DateTime.to_unix() end)
    skew = Keyword.get(opts, :clock_skew_seconds, 30)

    valid? =
      response_bound?(response, issuer, audience) and
        valid_response_identifiers?(response) and
        valid_response_times?(response, now, skew) and
        valid_response_scope?(response, scopes)

    if valid?,
      do: {:ok, response},
      else: {:error, Error.new(:invalid_token, stage: :introspection_response)}
  end

  def validate_response(_response, _opts),
    do: {:error, Error.new(:invalid_token, stage: :introspection_response)}

  defp valid_active_claims?(claims) do
    Enum.all?(~w(iss sub aud client_id scope jti), fn key ->
      is_binary(claims[key]) and claims[key] != ""
    end) and is_integer(claims["iat"]) and is_integer(claims["exp"]) and
      claims["exp"] > claims["iat"]
  end

  defp response_bound?(response, issuer, audience),
    do: response["iss"] == issuer and response["aud"] == audience

  defp valid_response_identifiers?(response) do
    Enum.all?(~w(sub client_id grant_id jti), fn key ->
      is_binary(response[key]) and response[key] != ""
    end)
  end

  defp valid_response_times?(response, now, skew) do
    is_integer(response["iat"]) and is_integer(response["exp"]) and
      response["iat"] <= now + skew and response["exp"] > response["iat"] and
      response["exp"] > now - skew
  end

  defp valid_response_scope?(response, scopes),
    do: match?({:ok, _normalized}, Scope.normalize(response["scope"], scopes))
end
