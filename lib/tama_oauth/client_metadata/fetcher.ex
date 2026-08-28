defmodule TamaOAuth.ClientMetadata.Fetcher do
  @moduledoc "A fetch behaviour for OAuth Client ID Metadata Documents."

  @callback fetch(String.t(), keyword()) ::
              {:ok,
               %{
                 body: binary(),
                 document: map(),
                 url: String.t(),
                 cache_ttl: non_neg_integer() | nil
               }}
              | {:error, term()}
end
