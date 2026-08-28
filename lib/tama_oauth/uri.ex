defmodule TamaOAuth.URI do
  @moduledoc """
  OAuth URI validation helpers, including native-app loopback redirects.
  """

  @client_segment ~r/^[A-Za-z0-9_-]+$/

  @spec normalize(term()) :: {:ok, String.t()} | {:error, :invalid_uri}
  def normalize(value) when is_binary(value) do
    with %Elixir.URI{scheme: scheme, host: host, userinfo: nil, fragment: nil} = uri <-
           Elixir.URI.parse(value),
         true <- scheme in ["http", "https"] and is_binary(host) and host != "" do
      uri = %{
        uri
        | scheme: String.downcase(scheme),
          host: String.downcase(host),
          path: normalize_path(uri.path)
      }

      {:ok, Elixir.URI.to_string(uri)}
    else
      _ -> {:error, :invalid_uri}
    end
  end

  def normalize(_value), do: {:error, :invalid_uri}

  @spec web_url?(term(), keyword()) :: boolean()
  def web_url?(value, opts \\ []) do
    allow_local? = Keyword.get(opts, :allow_local?, false)
    https_ports = Keyword.get(opts, :https_ports, [443])

    case Elixir.URI.parse(value) do
      %Elixir.URI{scheme: "https", host: host, port: port, userinfo: nil, fragment: nil}
      when is_binary(host) ->
        port in https_ports

      %Elixir.URI{scheme: "http", host: host, userinfo: nil, fragment: nil}
      when is_binary(host) ->
        allow_local? and loopback_host?(host)

      _ ->
        false
    end
  rescue
    _ -> false
  end

  @spec same_origin?(term(), term()) :: boolean()
  def same_origin?(left, right) when is_binary(left) and is_binary(right) do
    with {:ok, left_origin} <- origin(left),
         {:ok, right_origin} <- origin(right) do
      left_origin == right_origin
    else
      _ -> false
    end
  end

  def same_origin?(_left, _right), do: false

  @spec valid_redirect?(term(), keyword()) :: boolean()
  def valid_redirect?(value, opts \\ [])

  def valid_redirect?(value, opts) when is_binary(value) do
    allow_local? = Keyword.get(opts, :allow_local?, true)

    case Elixir.URI.parse(value) do
      %Elixir.URI{scheme: "https", host: host, userinfo: nil, fragment: nil}
      when is_binary(host) ->
        true

      %Elixir.URI{scheme: "http", host: host, path: path, userinfo: nil, fragment: nil}
      when is_binary(host) and is_binary(path) ->
        allow_local? and loopback_host?(host)

      _ ->
        false
    end
  end

  def valid_redirect?(_value, _opts), do: false

  @spec redirect_allowed?(term(), term()) :: boolean()
  def redirect_allowed?(requested, registered_uris)
      when is_binary(requested) and is_list(registered_uris) do
    requested in registered_uris or
      Enum.any?(registered_uris, &ephemeral_loopback_match?(requested, &1))
  end

  def redirect_allowed?(_requested, _registered_uris), do: false

  @spec scoped_client_id?(term(), term()) :: boolean()
  def scoped_client_id?(client_id, prefix) when is_binary(client_id) and is_binary(prefix) do
    scoped_client_uri?(Elixir.URI.parse(client_id), Elixir.URI.parse(prefix))
  end

  def scoped_client_id?(_client_id, _prefix), do: false

  @spec protected_resource_metadata_uri(String.t()) ::
          {:ok, String.t()} | {:error, :invalid_uri}
  def protected_resource_metadata_uri(resource) do
    with {:ok, normalized} <- normalize(resource) do
      uri = Elixir.URI.parse(normalized)
      path = "/.well-known/oauth-protected-resource" <> (uri.path || "")
      {:ok, Elixir.URI.to_string(%{uri | path: path, query: nil, fragment: nil})}
    end
  end

  @spec loopback_host?(term()) :: boolean()
  def loopback_host?(host), do: host in ["127.0.0.1", "localhost", "[::1]", "::1"]

  defp origin(value) do
    case Elixir.URI.parse(value) do
      %Elixir.URI{scheme: scheme, host: host, port: port, userinfo: nil, fragment: nil}
      when scheme in ["http", "https"] and is_binary(host) ->
        {:ok, {scheme, String.downcase(host), port}}

      _ ->
        {:error, :invalid_uri}
    end
  end

  defp normalize_path(path) when path in [nil, ""], do: nil
  defp normalize_path(path), do: path

  defp ephemeral_loopback_match?(requested, registered) do
    requested_uri = Elixir.URI.parse(requested)
    registered_uri = Elixir.URI.parse(registered)

    same_loopback_origin?(requested_uri, registered_uri) and
      valid_ephemeral_port?(requested_uri, registered) and
      same_redirect_target?(requested_uri, registered_uri)
  end

  defp same_loopback_origin?(requested, registered) do
    loopback_host?(requested.host) and loopback_host?(registered.host) and
      requested.scheme == "http" and registered.scheme == "http" and
      requested.host == registered.host
  end

  defp valid_ephemeral_port?(requested, registered) do
    requested.port not in [nil, 80] and not explicit_port?(registered)
  end

  defp same_redirect_target?(requested, registered) do
    requested.path == registered.path and requested.query == registered.query and
      requested.fragment == registered.fragment and requested.userinfo == registered.userinfo
  end

  defp explicit_port?(value) do
    String.match?(value, ~r{\Ahttps?://(?:\[[^\]]+\]|[^/?#:]+):\d+(?:[/?#]|\z)})
  end

  defp scoped_client_uri?(
         %Elixir.URI{
           scheme: "https",
           host: host,
           port: port,
           path: path,
           userinfo: nil,
           query: nil,
           fragment: nil
         },
         %Elixir.URI{
           scheme: "https",
           host: host,
           port: port,
           path: prefix_path,
           userinfo: nil,
           query: nil,
           fragment: nil
         }
       )
       when is_binary(path) and is_binary(prefix_path) do
    case String.split(path, prefix_path, parts: 2) do
      ["", remainder] ->
        case String.split(remainder, "/") do
          [segment, "client.json"] -> String.match?(segment, @client_segment)
          _ -> false
        end

      _ ->
        false
    end
  end

  defp scoped_client_uri?(_client, _prefix), do: false
end
