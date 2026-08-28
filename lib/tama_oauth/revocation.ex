defmodule TamaOAuth.Revocation do
  @moduledoc "Parses bounded RFC 7009 token revocation requests."

  alias TamaOAuth.Error

  @max_token_bytes 16_384
  @max_client_id_bytes 2_048

  @enforce_keys [:token, :client_id]
  defstruct @enforce_keys ++ [:token_type_hint]

  @type t :: %__MODULE__{
          token: String.t(),
          client_id: String.t(),
          token_type_hint: String.t() | nil
        }

  @spec parse(map(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def parse(params, opts \\ [])

  def parse(%{"token" => token, "client_id" => client_id} = params, opts) do
    max_token_bytes = Keyword.get(opts, :max_token_bytes, @max_token_bytes)
    max_client_id_bytes = Keyword.get(opts, :max_client_id_bytes, @max_client_id_bytes)
    hint = params["token_type_hint"]

    valid? =
      sized?(token, max_token_bytes) and sized?(client_id, max_client_id_bytes) and
        hint in [nil, "access_token", "refresh_token"]

    if valid?,
      do: {:ok, %__MODULE__{token: token, client_id: client_id, token_type_hint: hint}},
      else: invalid_request()
  end

  def parse(_params, _opts), do: invalid_request()

  @spec response() :: :ok
  def response, do: :ok

  defp sized?(value, max), do: is_binary(value) and byte_size(value) in 1..max
  defp invalid_request, do: {:error, Error.new(:invalid_request, stage: :revocation_request)}
end
