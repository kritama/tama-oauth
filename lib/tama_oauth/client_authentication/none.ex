defmodule TamaOAuth.ClientAuthentication.None do
  @moduledoc "Validates public clients using `token_endpoint_auth_method=none`."

  alias TamaOAuth.{ClientMetadata, Error}

  @spec authenticate(map()) :: {:ok, String.t()} | {:error, Error.t()}
  def authenticate(%{
        client_id: client_id,
        metadata: %ClientMetadata{} = metadata,
        params: params,
        authorization_headers: []
      })
      when is_binary(client_id) and is_map(params) do
    forbidden = ["client_assertion", "client_assertion_type", "client_secret"]

    valid? =
      client_id == metadata.client_id and
        "none" in metadata.token_endpoint_auth_methods_supported and
        Enum.all?(forbidden, &(not Map.has_key?(params, &1)))

    if valid?,
      do: {:ok, client_id},
      else: {:error, Error.new(:invalid_client, stage: :method_detection)}
  end

  def authenticate(_context),
    do: {:error, Error.new(:invalid_client, stage: :method_detection)}
end
