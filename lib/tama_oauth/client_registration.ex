defmodule TamaOAuth.ClientRegistration do
  @moduledoc """
  Normalizes public-client Dynamic Client Registration metadata.

  This is a compatibility boundary for RFC 7591 clients. Applications own
  generated client IDs, persistence, lifecycle, rate limits, and cleanup.
  """

  alias TamaOAuth.{Crypto, Error, Scope, URI}

  @max_members 32
  @max_list_values 8
  @max_name_bytes 128
  @max_uri_bytes 2_048
  @grant_types ["authorization_code", "refresh_token"]
  @response_types ["code"]

  @enforce_keys [
    :application_type,
    :client_name,
    :redirect_uris,
    :grant_types,
    :response_types,
    :token_endpoint_auth_method,
    :metadata_digest
  ]
  defstruct @enforce_keys ++ [:client_uri, :scope]

  @type t :: %__MODULE__{}

  @spec normalize(map(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def normalize(params, opts \\ [])

  def normalize(params, opts) when is_map(params) and map_size(params) <= @max_members do
    supported_scopes = Keyword.fetch!(opts, :supported_scopes)

    with {:ok, requested_application_type} <- application_type(params),
         {:ok, client_name} <- client_name(params["client_name"]),
         {:ok, client_uri} <- client_uri(params["client_uri"]),
         {:ok, redirect_uris, application_type} <-
           redirect_uris(params["redirect_uris"], requested_application_type),
         :ok <- fixed_list(params["grant_types"], @grant_types, :grant_types),
         :ok <- fixed_list(params["response_types"], @response_types, :response_types),
         :ok <- authentication_method(params["token_endpoint_auth_method"]),
         {:ok, scope} <- optional_scope(params["scope"], supported_scopes) do
      normalized = %{
        application_type: application_type,
        client_name: client_name,
        client_uri: client_uri,
        redirect_uris: Enum.sort(redirect_uris),
        grant_types: @grant_types,
        response_types: @response_types,
        token_endpoint_auth_method: "none",
        scope: scope
      }

      {:ok, struct!(__MODULE__, Map.put(normalized, :metadata_digest, digest(normalized)))}
    end
  end

  def normalize(_params, _opts), do: invalid_metadata(:metadata_shape)

  @spec digest(map() | t()) :: binary()
  def digest(%__MODULE__{} = registration),
    do: registration |> Map.from_struct() |> Map.delete(:metadata_digest) |> digest()

  def digest(metadata) when is_map(metadata) do
    metadata
    |> canonical_tuple()
    |> :erlang.term_to_binary([:deterministic])
    |> Crypto.digest()
  end

  defp canonical_tuple(metadata) do
    {
      1,
      metadata.application_type,
      metadata.client_name,
      metadata.client_uri,
      Enum.sort(metadata.redirect_uris),
      metadata.grant_types,
      metadata.response_types,
      metadata.token_endpoint_auth_method,
      metadata.scope
    }
  end

  defp application_type(params) do
    case Map.fetch(params, "application_type") do
      :error -> {:ok, nil}
      {:ok, type} when type in ["native", "web"] -> {:ok, type}
      {:ok, _type} -> invalid_metadata(:application_type)
    end
  end

  defp client_name(value) when is_binary(value) and byte_size(value) <= @max_name_bytes do
    normalized = String.trim(value)

    if normalized != "" and not String.match?(normalized, ~r/[\x00-\x1F\x7F]/),
      do: {:ok, normalized},
      else: invalid_metadata(:metadata_shape)
  end

  defp client_name(_value), do: invalid_metadata(:metadata_shape)

  defp client_uri(nil), do: {:ok, nil}

  defp client_uri(value) when is_binary(value) and byte_size(value) <= @max_uri_bytes do
    if URI.web_url?(value), do: {:ok, value}, else: invalid_metadata(:client_uri)
  end

  defp client_uri(_value), do: invalid_metadata(:client_uri)

  defp redirect_uris(values, application_type)
       when is_list(values) and values != [] and length(values) <= @max_list_values do
    with true <- values == Enum.uniq(values),
         {:ok, normalized_application_type} <-
           normalize_application_type(values, application_type) do
      {:ok, values, normalized_application_type}
    else
      _ -> invalid_redirect()
    end
  end

  defp redirect_uris(_values, _application_type), do: invalid_redirect()

  defp normalize_application_type(values, nil) do
    case values |> Enum.map(&redirect_type/1) |> Enum.uniq() do
      [type] when type in ["native", "web"] -> {:ok, type}
      _ -> :error
    end
  end

  defp normalize_application_type(values, application_type) do
    if Enum.all?(values, &valid_redirect?(&1, application_type)),
      do: {:ok, application_type},
      else: :error
  end

  defp redirect_type(value) do
    cond do
      valid_redirect?(value, "native") -> "native"
      valid_redirect?(value, "web") -> "web"
      true -> :invalid
    end
  end

  defp valid_redirect?(value, "web")
       when is_binary(value) and byte_size(value) <= @max_uri_bytes do
    case Elixir.URI.new(value) do
      {:ok, %Elixir.URI{scheme: "https", host: host, port: port, userinfo: nil, fragment: nil}}
      when is_binary(host) and port in 1..65_535 ->
        true

      _ ->
        false
    end
  end

  defp valid_redirect?(value, "native")
       when is_binary(value) and byte_size(value) <= @max_uri_bytes do
    uri = Elixir.URI.parse(value)

    native_loopback?(uri) and valid_native_port?(uri, value) and
      valid_native_path?(uri.path) and is_nil(uri.userinfo) and is_nil(uri.fragment)
  rescue
    _ -> false
  end

  defp valid_redirect?(_value, _application_type), do: false

  defp explicit_port?(value),
    do: String.match?(value, ~r{\Ahttp://(?:\[[^\]]+\]|[^/?#:]+):\d+(?:[/?#]|\z)})

  defp native_loopback?(uri), do: uri.scheme == "http" and URI.loopback_host?(uri.host)

  defp valid_native_port?(uri, value),
    do: is_integer(uri.port) and uri.port in 1_024..65_535 and explicit_port?(value)

  defp valid_native_path?(path),
    do: is_binary(path) and path != "" and String.starts_with?(path, "/")

  defp fixed_list(values, expected, stage)
       when is_list(values) and values != [] and length(values) <= @max_list_values do
    if values == Enum.uniq(values) and Enum.sort(values) == Enum.sort(expected),
      do: :ok,
      else: invalid_metadata(stage)
  end

  defp fixed_list(_values, _expected, stage), do: invalid_metadata(stage)

  defp authentication_method("none"), do: :ok
  defp authentication_method(_method), do: invalid_metadata(:authentication_method)

  defp optional_scope(nil, _supported), do: {:ok, nil}
  defp optional_scope(value, supported), do: Scope.normalize(value, supported, max_bytes: 256)

  defp invalid_redirect,
    do:
      {:error,
       Error.new(:invalid_redirect_uri, stage: :redirect_uris, details: %{kind: :redirect_uri})}

  defp invalid_metadata(stage),
    do:
      {:error,
       Error.new(:invalid_client_metadata, stage: stage, details: %{kind: :client_metadata})}
end
