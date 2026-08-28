defmodule TamaOAuth.ClientMetadata do
  @moduledoc """
  Validates OAuth Client ID Metadata Documents and returns normalized metadata.

  The caller decides which client IDs may be fetched and owns caching and
  persistence. This module guarantees that successful metadata is bound to the
  exact client ID URL and contains no symmetric client credentials.
  """

  alias TamaOAuth.{Crypto, URI}

  @default_methods ["none", "private_key_jwt"]
  @default_algorithms ["RS256"]
  @forbidden_methods ~w(client_secret_basic client_secret_post client_secret_jwt)
  @max_client_id_bytes 2_048
  @max_client_name_bytes 256
  @max_list_items 32
  @max_item_bytes 2_048

  @enforce_keys [
    :client_id,
    :client_name,
    :redirect_uris,
    :grant_types,
    :response_types,
    :token_endpoint_auth_methods_supported,
    :token_endpoint_auth_signing_algorithms
  ]
  defstruct @enforce_keys ++
              [
                :client_uri,
                :jwks_uri,
                :metadata_digest,
                :validated_url,
                :cache_ttl,
                registration_type: :cimd,
                verified_client_metadata?: true
              ]

  @type t :: %__MODULE__{}

  @spec fetch(String.t(), keyword()) :: {:ok, t()} | {:error, atom()}
  def fetch(client_id, opts \\ []) do
    fetcher = Keyword.get(opts, :fetcher, TamaOAuth.ClientMetadata.ReqFetcher)

    fetch_opts =
      opts
      |> Keyword.get(:fetch_options, [])
      |> Keyword.put(:origin, client_id)
      |> Keyword.put_new(:allow_local?, Keyword.get(opts, :allow_local?, false))

    with true <- valid_client_id_url?(client_id, opts),
         {:ok, response} <- fetcher.fetch(client_id, fetch_opts),
         {:ok, metadata} <- validate(response.document, client_id, opts) do
      {:ok,
       %{
         metadata
         | metadata_digest: Crypto.digest(response.body),
           validated_url: response.url,
           cache_ttl: response.cache_ttl
       }}
    else
      {:error, reason} when reason in [:timeout, :unavailable] ->
        {:error, :temporarily_unavailable}

      _ ->
        {:error, :invalid_client}
    end
  end

  @spec validate(map(), String.t(), keyword()) :: {:ok, t()} | {:error, atom()}
  def validate(document, client_id, opts \\ [])

  def validate(document, client_id, opts) when is_map(document) and is_binary(client_id) do
    server_methods = Keyword.get(opts, :auth_methods, @default_methods)
    server_algorithms = Keyword.get(opts, :signing_algorithms, @default_algorithms)

    with true <- valid_client_id_url?(client_id, opts),
         true <- document["client_id"] == client_id,
         {:ok, client_name} <- validate_client_name(document["client_name"]),
         :ok <- reject_symmetric_credentials(document),
         {:ok, client_uri} <- validate_optional_uri(document["client_uri"], opts),
         {:ok, redirect_uris} <- validate_redirects(document["redirect_uris"], opts),
         {:ok, grant_types} <- validate_grant_types(document["grant_types"]),
         {:ok, response_types} <- validate_response_types(document["response_types"]),
         {:ok, methods} <- normalize_methods(document, server_methods),
         {:ok, algorithms} <- normalize_algorithms(document, server_algorithms, methods),
         {:ok, jwks_uri} <- validate_jwks_uri(document["jwks_uri"], client_id, methods, opts) do
      {:ok,
       %__MODULE__{
         client_id: client_id,
         client_name: client_name,
         client_uri: client_uri,
         redirect_uris: redirect_uris,
         grant_types: grant_types,
         response_types: response_types,
         token_endpoint_auth_methods_supported: methods,
         token_endpoint_auth_signing_algorithms: algorithms,
         jwks_uri: jwks_uri
       }}
    else
      _ -> {:error, :invalid_client_metadata}
    end
  end

  def validate(_document, _client_id, _opts), do: {:error, :invalid_client_metadata}

  @spec valid_client_id_url?(term(), keyword()) :: boolean()
  def valid_client_id_url?(client_id, opts \\ []) do
    allow_local? = Keyword.get(opts, :allow_local?, false)

    byte_size_valid? =
      is_binary(client_id) and byte_size(client_id) in 1..@max_client_id_bytes

    byte_size_valid? and URI.web_url?(client_id, allow_local?: allow_local?) and
      case Elixir.URI.parse(client_id) do
        %Elixir.URI{path: path, query: nil, fragment: nil} -> is_binary(path) and path != ""
        _ -> false
      end
  end

  @spec redirect_allowed?(String.t(), t() | [String.t()]) :: boolean()
  def redirect_allowed?(redirect_uri, %__MODULE__{redirect_uris: uris}),
    do: URI.redirect_allowed?(redirect_uri, uris)

  def redirect_allowed?(redirect_uri, uris), do: URI.redirect_allowed?(redirect_uri, uris)

  defp validate_client_name(value) do
    if is_binary(value) and byte_size(value) in 1..@max_client_name_bytes and
         String.trim(value) != "",
       do: {:ok, value},
       else: {:error, :invalid_client_name}
  end

  defp reject_symmetric_credentials(document) do
    methods =
      document
      |> Map.get("token_endpoint_auth_methods_supported", [])
      |> List.wrap()

    forbidden? =
      Enum.any?(@forbidden_methods, &(&1 in methods)) or
        Map.has_key?(document, "client_secret") or
        Map.has_key?(document, "client_secret_expires_at")

    if forbidden?, do: {:error, :symmetric_credentials}, else: :ok
  end

  defp validate_optional_uri(nil, _opts), do: {:ok, nil}

  defp validate_optional_uri(value, opts) do
    if URI.web_url?(value, allow_local?: Keyword.get(opts, :allow_local?, false)),
      do: {:ok, value},
      else: {:error, :invalid_uri}
  end

  defp validate_redirects(values, opts) do
    valid? =
      bounded_unique_strings?(values) and
        Enum.all?(
          values,
          &URI.valid_redirect?(&1, allow_local?: Keyword.get(opts, :allow_local?, true))
        )

    if valid?, do: {:ok, values}, else: {:error, :invalid_redirect_uris}
  end

  defp validate_grant_types(nil), do: {:ok, ["authorization_code"]}

  defp validate_grant_types(values) do
    if bounded_unique_strings?(values) and "authorization_code" in values and
         Enum.all?(values, &(&1 in ["authorization_code", "refresh_token"])),
       do: {:ok, values},
       else: {:error, :invalid_grant_types}
  end

  defp validate_response_types(nil), do: {:ok, ["code"]}

  defp validate_response_types(values) do
    if bounded_unique_strings?(values) and values == ["code"],
      do: {:ok, values},
      else: {:error, :invalid_response_types}
  end

  defp normalize_methods(document, server_methods) do
    values =
      case Map.fetch(document, "token_endpoint_auth_methods_supported") do
        {:ok, methods} -> methods
        :error -> List.wrap(Map.get(document, "token_endpoint_auth_method", "none"))
      end

    valid? =
      bounded_unique_strings?(values) and Enum.all?(values, &(&1 in @default_methods)) and
        Enum.any?(values, &(&1 in server_methods))

    if valid?, do: {:ok, values}, else: {:error, :invalid_auth_methods}
  end

  defp normalize_algorithms(document, server_algorithms, methods) do
    values =
      case Map.fetch(document, "token_endpoint_auth_signing_alg_values_supported") do
        {:ok, algorithms} -> algorithms
        :error -> List.wrap(document["token_endpoint_auth_signing_alg"])
      end

    cond do
      "private_key_jwt" not in methods ->
        {:ok, []}

      values == [] ->
        {:ok, server_algorithms}

      bounded_unique_strings?(values) and Enum.any?(values, &(&1 in server_algorithms)) ->
        {:ok, values}

      true ->
        {:error, :invalid_signing_algorithms}
    end
  end

  defp validate_jwks_uri(jwks_uri, client_id, methods, opts) do
    if "private_key_jwt" in methods do
      valid? =
        URI.web_url?(jwks_uri, allow_local?: Keyword.get(opts, :allow_local?, false)) and
          URI.same_origin?(jwks_uri, client_id)

      if valid?, do: {:ok, jwks_uri}, else: {:error, :invalid_jwks_uri}
    else
      {:ok, nil}
    end
  end

  defp bounded_unique_strings?(values) do
    is_list(values) and values != [] and length(values) <= @max_list_items and
      values == Enum.uniq(values) and
      Enum.all?(values, &(is_binary(&1) and byte_size(&1) in 1..@max_item_bytes))
  end
end
