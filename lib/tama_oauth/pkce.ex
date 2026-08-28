defmodule TamaOAuth.PKCE do
  @moduledoc """
  PKCE `S256` validation and verification as defined by RFC 7636.
  """

  alias TamaOAuth.Crypto

  @value ~r/^[A-Za-z0-9._~-]+$/

  @spec valid_challenge?(term()) :: boolean()
  def valid_challenge?(value), do: valid_value?(value)

  @spec valid_verifier?(term()) :: boolean()
  def valid_verifier?(value), do: valid_value?(value)

  @spec challenge(String.t()) :: {:ok, String.t()} | {:error, :invalid_verifier}
  def challenge(verifier) do
    if valid_verifier?(verifier) do
      challenge = verifier |> Crypto.digest() |> Base.url_encode64(padding: false)
      {:ok, challenge}
    else
      {:error, :invalid_verifier}
    end
  end

  @spec verify(term(), term()) :: boolean()
  def verify(verifier, expected_challenge) when is_binary(expected_challenge) do
    case challenge(verifier) do
      {:ok, actual} -> Crypto.secure_compare(actual, expected_challenge)
      {:error, :invalid_verifier} -> false
    end
  end

  def verify(_verifier, _expected_challenge), do: false

  defp valid_value?(value) do
    is_binary(value) and byte_size(value) in 43..128 and String.match?(value, @value)
  end
end
