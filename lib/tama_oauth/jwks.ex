defmodule TamaOAuth.JWKS do
  @moduledoc """
  Validates, selects, and publishes JSON Web Key Sets.

  Private key parameters are rejected at verification boundaries and stripped
  when producing a public JWKS document.
  """

  @max_keys 32
  @max_kid_bytes 128
  @private_parameters ~w(d p q dp dq qi oth k)

  defmodule Set do
    @moduledoc "A validated JWKS indexed by key ID."
    @enforce_keys [:keys]
    defstruct [:keys]
  end

  @type t :: %Set{keys: %{String.t() => map()}}

  @spec fetch(String.t(), String.t(), keyword()) :: {:ok, t()} | {:error, atom()}
  def fetch(jwks_uri, client_id, opts \\ []) do
    remote_json = Keyword.get(opts, :remote_json, TamaOAuth.RemoteJSON)

    fetch_options =
      opts
      |> Keyword.get(:fetch_options, [])
      |> Keyword.put(:origin, client_id)
      |> Keyword.put(:content_types, ["application/json", "application/jwk-set+json"])

    with {:ok, response} <- remote_json.fetch(jwks_uri, fetch_options),
         {:ok, set} <- validate(response.document, opts) do
      {:ok, set}
    else
      {:error, reason} when reason in [:timeout, :unavailable] ->
        {:error, :temporarily_unavailable}

      _ ->
        {:error, :invalid_jwks}
    end
  end

  @spec validate(map(), keyword()) :: {:ok, t()} | {:error, atom()}
  def validate(document, opts \\ [])

  def validate(%{"keys" => keys}, opts)
      when is_list(keys) and keys != [] and length(keys) <= @max_keys do
    max_keys = Keyword.get(opts, :max_keys, @max_keys)

    if length(keys) <= max_keys do
      validate_keys(keys)
    else
      {:error, :invalid_jwks}
    end
  end

  def validate(_document, _opts), do: {:error, :invalid_jwks}

  @spec select(t() | map(), String.t(), String.t(), keyword()) ::
          {:ok, map()} | {:error, atom()}
  def select(jwks, kid, algorithm, opts \\ [])

  def select(%{"keys" => _keys} = document, kid, algorithm, opts) do
    with {:ok, set} <- validate(document, opts) do
      select(set, kid, algorithm, opts)
    end
  end

  def select(%Set{} = set, kid, algorithm, opts)
      when is_binary(kid) and byte_size(kid) in 1..@max_kid_bytes and is_binary(algorithm) do
    allowed = Keyword.get(opts, :algorithms, ["RS256"])

    with true <- algorithm in allowed,
         {:ok, key} <- Map.fetch(set.keys, kid),
         :ok <- validate_verification_key(key, algorithm) do
      {:ok, key}
    else
      :error -> {:error, :unknown_kid}
      _ -> {:error, :ineligible_jwk}
    end
  end

  def select(_jwks, _kid, _algorithm, _opts), do: {:error, :ineligible_jwk}

  @spec public_document([term()]) :: {:ok, map()} | {:error, atom()}
  def public_document(keys) when is_list(keys) and keys != [] and length(keys) <= @max_keys do
    with {:ok, public_keys} <- public_keys(keys),
         true <- Enum.all?(public_keys, &public_signing_key?/1),
         {:ok, _set} <- validate(%{"keys" => public_keys}) do
      {:ok, %{"keys" => public_keys}}
    else
      _ -> {:error, :invalid_jwks}
    end
  end

  def public_document(_keys), do: {:error, :invalid_jwks}

  defp validate_keys(keys) do
    Enum.reduce_while(keys, {:ok, %Set{keys: %{}}}, &validate_key/2)
  end

  defp validate_key(key, {:ok, set}) do
    with {:ok, kid, key} <- validate_jwk(key),
         false <- Map.has_key?(set.keys, kid) do
      {:cont, {:ok, %{set | keys: Map.put(set.keys, kid, key)}}}
    else
      _ -> {:halt, {:error, :invalid_jwks}}
    end
  end

  defp public_keys(keys) do
    Enum.reduce_while(keys, {:ok, []}, fn key, {:ok, acc} ->
      case public_key(key) do
        {:ok, public} -> {:cont, {:ok, [public | acc]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
    |> case do
      {:ok, values} -> {:ok, Enum.reverse(values)}
      error -> error
    end
  end

  defp public_key(%JOSE.JWK{} = key) do
    {_fields, public} = key |> JOSE.JWK.to_public() |> JOSE.JWK.to_map()
    {:ok, public}
  rescue
    _ -> {:error, :invalid_jwk}
  end

  defp public_key(key) when is_map(key) do
    metadata = Map.take(key, ["kid", "alg", "use", "key_ops"])
    {_fields, public} = key |> JOSE.JWK.from_map() |> JOSE.JWK.to_public_map()
    {:ok, Map.merge(public, metadata)}
  rescue
    _ -> {:error, :invalid_jwk}
  end

  defp public_key(_key), do: {:error, :invalid_jwk}

  defp validate_jwk(%{"kid" => kid} = key)
       when is_binary(kid) and byte_size(kid) in 1..@max_kid_bytes do
    _jwk = JOSE.JWK.from_map(key)
    {:ok, kid, key}
  rescue
    _ -> {:error, :invalid_jwk}
  end

  defp validate_jwk(_key), do: {:error, :invalid_jwk}

  defp validate_verification_key(%{"kty" => kty} = key, algorithm)
       when kty in ["RSA", "EC"] do
    valid? =
      Enum.all?(@private_parameters, &(not Map.has_key?(key, &1))) and
        key["use"] in [nil, "sig"] and valid_key_operations?(key["key_ops"]) and
        valid_type?(kty, algorithm) and key["alg"] in [nil, algorithm] and strong_key?(key)

    if valid?, do: :ok, else: {:error, :ineligible_jwk}
  end

  defp validate_verification_key(_key, _algorithm), do: {:error, :ineligible_jwk}

  defp public_signing_key?(%{"kty" => kty, "kid" => kid} = key)
       when kty in ["RSA", "EC"] and is_binary(kid) do
    Enum.all?(@private_parameters, &(not Map.has_key?(key, &1))) and key["use"] in [nil, "sig"]
  end

  defp public_signing_key?(_key), do: false

  defp valid_key_operations?(nil), do: true

  defp valid_key_operations?(operations) when is_list(operations),
    do: "verify" in operations and Enum.all?(operations, &is_binary/1)

  defp valid_key_operations?(_operations), do: false

  defp valid_type?("RSA", "RS" <> _rest), do: true
  defp valid_type?("RSA", "PS" <> _rest), do: true
  defp valid_type?("EC", "ES" <> _rest), do: true
  defp valid_type?(_type, _algorithm), do: false

  defp strong_key?(%{"kty" => "RSA", "n" => modulus, "e" => exponent}) do
    with {:ok, modulus_bytes, modulus_int} <- decode_unsigned(modulus),
         {:ok, _exponent_bytes, exponent_int} <- decode_unsigned(exponent) do
      bit_size(modulus_bytes) >= 2_048 and exponent_int >= 3 and rem(exponent_int, 2) == 1 and
        exponent_int < modulus_int
    else
      _ -> false
    end
  end

  defp strong_key?(%{"kty" => "EC", "crv" => curve}), do: curve in ["P-256", "P-384", "P-521"]
  defp strong_key?(_key), do: false

  defp decode_unsigned(value) when is_binary(value) do
    with {:ok, bytes} when bytes != "" <- Base.url_decode64(value, padding: false),
         integer when integer > 0 <- :binary.decode_unsigned(bytes) do
      {:ok, bytes, integer}
    else
      _ -> {:error, :invalid_integer}
    end
  end

  defp decode_unsigned(_value), do: {:error, :invalid_integer}
end
