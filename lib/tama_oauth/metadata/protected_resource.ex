defmodule TamaOAuth.Metadata.ProtectedResource do
  @moduledoc "Builds RFC 9728 protected-resource metadata."

  alias TamaOAuth.URI

  @spec build(keyword()) :: {:ok, map()} | {:error, :invalid_metadata}
  def build(opts) when is_list(opts) do
    resource = opts[:resource]
    authorization_servers = opts[:authorization_servers]
    scopes = opts[:scopes_supported]

    with {:ok, _resource} <- URI.normalize(resource),
         true <- valid_urls?(authorization_servers),
         true <- valid_strings?(scopes) do
      {:ok,
       %{
         "resource" => resource,
         "authorization_servers" => authorization_servers,
         "scopes_supported" => scopes,
         "bearer_methods_supported" => ["header"]
       }}
    else
      _ -> {:error, :invalid_metadata}
    end
  end

  def build(_opts), do: {:error, :invalid_metadata}

  defp valid_urls?(values) do
    is_list(values) and values != [] and
      Enum.all?(values, &match?({:ok, _normalized}, URI.normalize(&1)))
  end

  defp valid_strings?(values),
    do: is_list(values) and values != [] and Enum.all?(values, &(is_binary(&1) and &1 != ""))
end
