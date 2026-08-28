defmodule TamaOAuth.JWT do
  @moduledoc "Asymmetric JWT access-token signing and verification."

  alias TamaOAuth.{Error, JWKS, Scope}

  @max_token_bytes 16_384
  @max_kid_bytes 128

  @spec mint_access_token(map(), term(), keyword()) ::
          {:ok, String.t(), map()} | {:error, Error.t()}
  def mint_access_token(claims, key, opts) when is_map(claims) and is_list(opts) do
    algorithm = Keyword.get(opts, :algorithm, "RS256")
    kid = Keyword.fetch!(opts, :kid)
    now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now() |> DateTime.to_unix() end)
    ttl = Keyword.get(opts, :ttl, 600)

    claims = claims |> stringify_keys() |> Map.merge(%{"iat" => now, "exp" => now + ttl})

    with :ok <- validate_mint_inputs(claims, algorithm, kid, ttl),
         {:ok, token} <- sign(claims, key, algorithm, kid) do
      {:ok, token, claims}
    else
      {:error, %Error{} = error} -> {:error, error}
      _ -> {:error, Error.new(:temporarily_unavailable, stage: :token_signing)}
    end
  end

  @spec verify_access_token(String.t(), JWKS.t() | map(), keyword()) ::
          {:ok, map()} | {:error, Error.t()}
  def verify_access_token(token, jwks, opts) when is_binary(token) and is_list(opts) do
    algorithms = Keyword.get(opts, :algorithms, ["RS256"])

    with true <- byte_size(token) in 1..@max_token_bytes,
         {:ok, %{"alg" => algorithm, "kid" => kid}} <- peek_header(token),
         true <- algorithm in algorithms,
         true <- is_binary(kid) and byte_size(kid) in 1..@max_kid_bytes,
         {:ok, key} <- JWKS.select(jwks, kid, algorithm, algorithms: algorithms),
         {:ok, claims} <- verify_signature(token, key, algorithm),
         :ok <- validate_access_claims(claims, opts) do
      {:ok, claims}
    else
      _ -> {:error, Error.new(:invalid_token, stage: :access_token)}
    end
  end

  def verify_access_token(_token, _jwks, _opts),
    do: {:error, Error.new(:invalid_token, stage: :access_token)}

  @spec peek_header(String.t()) :: {:ok, map()} | {:error, :invalid_token}
  def peek_header(token) when is_binary(token) do
    case Joken.peek_header(token) do
      {:ok, header} when is_map(header) -> {:ok, header}
      _ -> {:error, :invalid_token}
    end
  rescue
    _ -> {:error, :invalid_token}
  end

  @spec verify_signature(String.t(), term(), String.t()) ::
          {:ok, map()} | {:error, :invalid_signature}
  def verify_signature(token, key, algorithm) do
    case Joken.Signer.verify(token, Joken.Signer.create(algorithm, key)) do
      {:ok, claims} when is_map(claims) -> {:ok, claims}
      _ -> {:error, :invalid_signature}
    end
  rescue
    _ -> {:error, :invalid_signature}
  end

  defp sign(claims, key, algorithm, kid) do
    Joken.Signer.sign(claims, Joken.Signer.create(algorithm, key, %{"kid" => kid}))
  rescue
    _ -> {:error, :signing_failed}
  end

  defp validate_mint_inputs(claims, algorithm, kid, ttl) do
    required = ~w(iss sub aud client_id scope jti)

    valid? =
      algorithm in ["RS256", "PS256", "ES256"] and is_binary(kid) and
        byte_size(kid) in 1..@max_kid_bytes and is_integer(ttl) and ttl > 0 and
        Enum.all?(required, &(is_binary(claims[&1]) and claims[&1] != ""))

    if valid?, do: :ok, else: {:error, Error.new(:invalid_request, stage: :token_claims)}
  end

  defp validate_access_claims(claims, opts) do
    issuer = Keyword.fetch!(opts, :issuer)
    audience = Keyword.fetch!(opts, :audience)
    scopes = Keyword.fetch!(opts, :scopes)
    now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now() |> DateTime.to_unix() end)
    skew = Keyword.get(opts, :clock_skew_seconds, 30)
    issued_at = claims["iat"]
    expires_at = claims["exp"]
    not_before = Map.get(claims, "nbf", issued_at)

    valid? =
      claims["iss"] == issuer and claims["aud"] == audience and
        Enum.all?(~w(sub client_id jti), &(is_binary(claims[&1]) and claims[&1] != "")) and
        valid_times?(issued_at, expires_at, not_before, now, skew) and
        match?({:ok, _scope}, Scope.normalize(claims["scope"], scopes))

    if valid?, do: :ok, else: {:error, :invalid_claims}
  end

  defp valid_times?(issued_at, expires_at, not_before, now, skew) do
    Enum.all?([issued_at, expires_at, not_before, now, skew], &is_integer/1) and
      issued_at <= now + skew and not_before <= now + skew and expires_at > now - skew and
      expires_at > issued_at
  end

  defp stringify_keys(map) do
    Map.new(map, fn
      {key, value} when is_atom(key) -> {Atom.to_string(key), value}
      pair -> pair
    end)
  end
end
