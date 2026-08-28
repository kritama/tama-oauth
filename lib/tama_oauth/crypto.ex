defmodule TamaOAuth.Crypto do
  @moduledoc """
  Cryptographic helpers for opaque OAuth credentials and their digests.
  """

  @spec opaque_token(pos_integer(), (pos_integer() -> binary())) :: String.t()
  def opaque_token(bytes \\ 32, random_bytes \\ &:crypto.strong_rand_bytes/1)
      when is_integer(bytes) and bytes > 0 and is_function(random_bytes, 1) do
    bytes
    |> random_bytes.()
    |> Base.url_encode64(padding: false)
  end

  @spec digest(binary()) :: binary()
  def digest(value) when is_binary(value), do: :crypto.hash(:sha256, value)

  @spec matches_digest?(term(), term()) :: boolean()
  def matches_digest?(value, expected) when is_binary(value) and is_binary(expected),
    do: secure_compare(digest(value), expected)

  def matches_digest?(_value, _expected), do: false

  @spec secure_compare(term(), term()) :: boolean()
  def secure_compare(left, right)
      when is_binary(left) and is_binary(right) and byte_size(left) == byte_size(right),
      do: :crypto.hash_equals(left, right)

  def secure_compare(_left, _right), do: false
end
