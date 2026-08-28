defmodule TamaOAuth.ClientMetadata.ReqFetcher do
  @moduledoc "The default SSRF-resistant Req client-metadata fetcher."

  @behaviour TamaOAuth.ClientMetadata.Fetcher

  @impl true
  def fetch(url, opts), do: TamaOAuth.RemoteJSON.fetch(url, opts)
end
