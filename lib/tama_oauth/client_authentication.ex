defmodule TamaOAuth.ClientAuthentication do
  @moduledoc "Routes explicit OAuth token-endpoint client authentication methods."

  alias TamaOAuth.ClientAuthentication.{None, PrivateKeyJWT}
  alias TamaOAuth.Error

  @spec authenticate(atom() | String.t(), map(), keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def authenticate(method, context, opts \\ [])

  def authenticate(method, context, _opts) when method in [:none, "none"],
    do: None.authenticate(context)

  def authenticate(method, context, opts)
      when method in [:private_key_jwt, "private_key_jwt"],
      do: PrivateKeyJWT.authenticate(context, opts)

  def authenticate(_method, _context, _opts),
    do: {:error, Error.new(:invalid_client, stage: :method_detection)}
end
