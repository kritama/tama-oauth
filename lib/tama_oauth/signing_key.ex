defmodule TamaOAuth.SigningKey do
  @moduledoc """
  Loads and validates application-owned asymmetric private signing keys.

  Applications remain responsible for obtaining and retaining private key
  material. This module owns bounded JSON decoding, JWK normalization, and
  cryptographic eligibility checks shared by package signing operations.
  """

  alias TamaOAuth.{Error, JWKS}

  @supported_algorithms ["RS256", "PS256", "ES256"]
  @max_encoded_key_bytes 65_536
  @max_kid_bytes 128

  @spec load(map() | String.t(), keyword()) :: {:ok, map()} | {:error, Error.t()}
  def load(source, opts) when is_list(opts) do
    algorithm = Keyword.get(opts, :algorithm, "RS256")
    algorithms = Keyword.get(opts, :algorithms, ["RS256"])
    kid = Keyword.get(opts, :kid)
    stage = Keyword.get(opts, :stage, :signing_key)

    with :ok <- validate_header(algorithm, algorithms, kid, stage),
         {:ok, key} <- decode(source, stage),
         {:ok, normalized} <- normalize(key, algorithm, kid, stage),
         {:ok, public_document} <- JWKS.public_document([normalized]),
         {:ok, _public_key} <-
           JWKS.select(public_document, kid, algorithm, algorithms: [algorithm]) do
      {:ok, normalized}
    else
      {:error, %Error{}} = error -> error
      _error -> invalid(stage)
    end
  end

  def load(_source, opts) when is_list(opts), do: invalid(Keyword.get(opts, :stage, :signing_key))
  def load(_source, _opts), do: invalid(:signing_key)

  @spec generate({:rsa, pos_integer()} | {:ec, atom()}, keyword()) ::
          {:ok, map()} | {:error, Error.t()}
  def generate(specification, opts) when is_list(opts) do
    with {:ok, key} <- generate_key(specification, opts) do
      load(key, opts)
    end
  end

  def generate(_specification, opts) when is_list(opts),
    do: invalid(Keyword.get(opts, :stage, :signing_key))

  def generate(_specification, _opts), do: invalid(:signing_key)

  defp validate_header(algorithm, algorithms, kid, stage) do
    valid? =
      is_list(algorithms) and algorithms != [] and
        Enum.all?(algorithms, &(&1 in @supported_algorithms)) and
        algorithm in algorithms and bounded_string?(kid, @max_kid_bytes)

    if valid?, do: :ok, else: invalid(stage)
  end

  defp decode(key, _stage) when is_map(key), do: {:ok, key}

  defp decode(encoded, stage)
       when is_binary(encoded) and byte_size(encoded) in 1..@max_encoded_key_bytes do
    case Jason.decode(encoded) do
      {:ok, key} when is_map(key) -> {:ok, key}
      _error -> invalid(stage)
    end
  end

  defp decode(_source, stage), do: invalid(stage)

  defp normalize(key, algorithm, kid, stage) do
    valid_metadata? =
      key["alg"] in [nil, algorithm] and key["kid"] in [nil, kid] and
        key["use"] in [nil, "sig"] and signing_operation?(key["key_ops"])

    normalized =
      key
      |> Map.delete("key_ops")
      |> Map.merge(%{"alg" => algorithm, "kid" => kid, "use" => "sig"})

    if valid_metadata? and private_signing_key?(normalized, algorithm),
      do: {:ok, normalized},
      else: invalid(stage)
  rescue
    _error -> invalid(stage)
  end

  defp generate_key({:rsa, bits}, opts) when bits >= 2_048 do
    algorithm = Keyword.get(opts, :algorithm, "RS256")

    if algorithm in ["RS256", "PS256"],
      do: jose_generate({:rsa, bits}, opts),
      else: invalid(Keyword.get(opts, :stage, :signing_key))
  end

  defp generate_key({:ec, curve}, opts) when curve in [:secp256r1, :prime256v1] do
    if Keyword.get(opts, :algorithm) == "ES256",
      do: jose_generate({:ec, curve}, opts),
      else: invalid(Keyword.get(opts, :stage, :signing_key))
  end

  defp generate_key(_specification, opts),
    do: invalid(Keyword.get(opts, :stage, :signing_key))

  defp jose_generate(specification, opts) do
    {_fields, key} = specification |> JOSE.JWK.generate_key() |> JOSE.JWK.to_map()
    {:ok, key}
  rescue
    _error -> invalid(Keyword.get(opts, :stage, :signing_key))
  end

  defp signing_operation?(nil), do: true

  defp signing_operation?(operations) when is_list(operations),
    do: "sign" in operations and Enum.all?(operations, &is_binary/1)

  defp signing_operation?(_operations), do: false

  defp private_signing_key?(%{"kty" => "RSA", "d" => d}, algorithm)
       when algorithm in ["RS256", "PS256"],
       do: is_binary(d) and d != ""

  defp private_signing_key?(%{"kty" => "EC", "crv" => "P-256", "d" => d}, "ES256"),
    do: is_binary(d) and d != ""

  defp private_signing_key?(_key, _algorithm), do: false

  defp bounded_string?(value, max_bytes)
       when is_binary(value) and byte_size(value) in 1..max_bytes//1 do
    String.trim(value) != "" and not String.match?(value, ~r/[\x00-\x1F\x7F]/)
  end

  defp bounded_string?(_value, _max_bytes), do: false

  defp invalid(stage), do: {:error, Error.new(:invalid_request, stage: stage)}
end
