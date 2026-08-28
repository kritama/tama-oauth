defmodule TamaOAuth.KeyProvider do
  @moduledoc "A behaviour for application-owned signing and verification keys."

  @callback signing_key() ::
              {:ok,
               %{
                 required(:kid) => String.t(),
                 required(:algorithm) => String.t(),
                 required(:key) => term()
               }}
              | {:error, term()}
  @callback verification_keys() :: {:ok, [term()]} | {:error, term()}
end
