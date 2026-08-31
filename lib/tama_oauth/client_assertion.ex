defmodule TamaOAuth.ClientAssertion do
  @moduledoc """
  Mints bounded RFC 7523 `private_key_jwt` client assertions.

  Applications own endpoint configuration, private-key custody, time, and
  replay-resistant assertion identifiers. This module validates those inputs,
  constructs the required header and claims, and signs the compact assertion.
  """

  alias TamaOAuth.{Error, JWKS, URI}

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @supported_algorithms ["RS256", "PS256", "ES256"]
  @max_identifier_bytes 2_048
  @max_jti_bytes 256
  @max_kid_bytes 128
  @max_assertion_bytes 16_384
  @max_lifetime_seconds 300

  @spec assertion_type() :: String.t()
  def assertion_type, do: @assertion_type

  @spec mint(String.t(), String.t(), map(), keyword()) ::
          {:ok, String.t(), map()} | {:error, Error.t()}
  def mint(client_id, audience, key, opts)
      when is_binary(client_id) and is_binary(audience) and is_map(key) and is_list(opts) do
    algorithm = Keyword.get(opts, :algorithm, "RS256")
    algorithms = Keyword.get(opts, :algorithms, ["RS256"])
    kid = Keyword.get(opts, :kid)
    jti = Keyword.get(opts, :jti)
    now = Keyword.get_lazy(opts, :now, fn -> DateTime.utc_now() |> DateTime.to_unix() end)
    ttl = Keyword.get(opts, :ttl, 60)
    max_lifetime = Keyword.get(opts, :max_lifetime_seconds, @max_lifetime_seconds)
    max_assertion_bytes = Keyword.get(opts, :max_assertion_bytes, @max_assertion_bytes)

    with :ok <- validate_claim_inputs(client_id, audience, jti),
         :ok <- validate_header_inputs(algorithm, algorithms, kid),
         :ok <- validate_interval(now, ttl, max_lifetime),
         {:ok, signing_key} <- validate_signing_key(key, algorithm, kid),
         claims <- claims(client_id, audience, jti, now, ttl),
         {:ok, assertion} <- sign(claims, signing_key, algorithm, kid),
         :ok <- validate_assertion_size(assertion, max_assertion_bytes) do
      {:ok, assertion, claims}
    end
  end

  def mint(_client_id, _audience, _key, _opts), do: invalid_request(:client_assertion)

  defp validate_claim_inputs(client_id, audience, jti) do
    valid? =
      bounded_string?(client_id, @max_identifier_bytes) and
        valid_uri?(audience) and
        bounded_string?(jti, @max_jti_bytes)

    if valid?, do: :ok, else: invalid_request(:client_assertion_claims)
  end

  defp validate_header_inputs(algorithm, algorithms, kid) do
    valid? =
      is_list(algorithms) and algorithms != [] and
        Enum.all?(algorithms, &(&1 in @supported_algorithms)) and
        algorithm in algorithms and
        bounded_string?(kid, @max_kid_bytes)

    if valid?, do: :ok, else: invalid_request(:client_assertion_header)
  end

  defp validate_interval(now, ttl, max_lifetime) do
    valid? =
      is_integer(now) and now >= 0 and is_integer(ttl) and is_integer(max_lifetime) and
        max_lifetime in 1..@max_lifetime_seconds and ttl in 1..max_lifetime

    if valid?, do: :ok, else: invalid_request(:client_assertion_claims)
  end

  defp validate_signing_key(key, algorithm, kid) do
    valid_metadata? =
      key["alg"] in [nil, algorithm] and key["kid"] in [nil, kid] and
        key["use"] in [nil, "sig"] and signing_operation?(key["key_ops"])

    normalized =
      key
      |> Map.delete("key_ops")
      |> Map.merge(%{"alg" => algorithm, "kid" => kid, "use" => "sig"})

    with true <- valid_metadata?,
         true <- private_signing_key?(normalized, algorithm),
         {:ok, public_jwks} <- JWKS.public_document([normalized]),
         {:ok, _public_key} <-
           JWKS.select(public_jwks, kid, algorithm, algorithms: [algorithm]) do
      {:ok, normalized}
    else
      _ -> invalid_request(:client_assertion_key)
    end
  end

  defp claims(client_id, audience, jti, now, ttl) do
    %{
      "iss" => client_id,
      "sub" => client_id,
      "aud" => audience,
      "jti" => jti,
      "iat" => now,
      "exp" => now + ttl
    }
  end

  defp sign(claims, key, algorithm, kid) do
    Joken.Signer.sign(claims, Joken.Signer.create(algorithm, key, %{"kid" => kid}))
  rescue
    _error -> temporarily_unavailable(:client_assertion_signing)
  end

  defp validate_assertion_size(assertion, max_bytes)
       when is_binary(assertion) and is_integer(max_bytes) and max_bytes > 0 do
    if byte_size(assertion) <= max_bytes,
      do: :ok,
      else: invalid_request(:client_assertion_size)
  end

  defp validate_assertion_size(_assertion, _max_bytes),
    do: invalid_request(:client_assertion_size)

  defp valid_uri?(value) when byte_size(value) in 1..@max_identifier_bytes do
    match?({:ok, _normalized}, URI.normalize(value))
  end

  defp valid_uri?(_value), do: false

  defp bounded_string?(value, max_bytes)
       when is_binary(value) and byte_size(value) in 1..max_bytes//1 do
    String.trim(value) != "" and not String.match?(value, ~r/[\x00-\x1F\x7F]/)
  end

  defp bounded_string?(_value, _max_bytes), do: false

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

  defp invalid_request(stage), do: {:error, Error.new(:invalid_request, stage: stage)}

  defp temporarily_unavailable(stage),
    do: {:error, Error.new(:temporarily_unavailable, stage: stage)}
end
