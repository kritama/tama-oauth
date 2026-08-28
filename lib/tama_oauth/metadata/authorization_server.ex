defmodule TamaOAuth.Metadata.AuthorizationServer do
  @moduledoc "Builds RFC 8414 authorization-server metadata."

  alias TamaOAuth.URI

  @required_urls [:issuer, :authorization_endpoint, :token_endpoint, :jwks_uri]

  @spec build(keyword()) :: {:ok, map()} | {:error, :invalid_metadata}
  def build(opts) when is_list(opts) do
    with true <- Enum.all?(@required_urls, &valid_url?(opts[&1])),
         true <- valid_optional_urls?(opts),
         true <- nonempty_strings?(opts[:scopes_supported]),
         true <- nonempty_strings?(opts[:token_endpoint_auth_methods_supported]),
         true <-
           nonempty_strings?(
             opts[:grant_types_supported] || ["authorization_code", "refresh_token"]
           ),
         true <- nonempty_strings?(opts[:response_types_supported] || ["code"]),
         true <- optional_strings?(opts[:token_endpoint_auth_signing_alg_values_supported]),
         true <- optional_urls?(opts[:protected_resources]),
         true <- is_boolean(Keyword.get(opts, :client_id_metadata_document_supported, true)) do
      metadata = %{
        "issuer" => opts[:issuer],
        "authorization_endpoint" => opts[:authorization_endpoint],
        "token_endpoint" => opts[:token_endpoint],
        "jwks_uri" => opts[:jwks_uri],
        "response_types_supported" => opts[:response_types_supported] || ["code"],
        "grant_types_supported" =>
          opts[:grant_types_supported] || ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported" => ["S256"],
        "token_endpoint_auth_methods_supported" => opts[:token_endpoint_auth_methods_supported],
        "scopes_supported" => opts[:scopes_supported],
        "client_id_metadata_document_supported" =>
          Keyword.get(opts, :client_id_metadata_document_supported, true),
        "authorization_response_iss_parameter_supported" => true
      }

      {:ok,
       metadata
       |> optional_url("registration_endpoint", opts[:registration_endpoint])
       |> optional_url("revocation_endpoint", opts[:revocation_endpoint])
       |> optional_url("introspection_endpoint", opts[:introspection_endpoint])
       |> optional_list("protected_resources", opts[:protected_resources])
       |> optional_list(
         "token_endpoint_auth_signing_alg_values_supported",
         opts[:token_endpoint_auth_signing_alg_values_supported]
       )}
    else
      _ -> {:error, :invalid_metadata}
    end
  end

  def build(_opts), do: {:error, :invalid_metadata}

  defp valid_url?(value), do: match?({:ok, _normalized}, URI.normalize(value))

  defp nonempty_strings?(values),
    do: is_list(values) and values != [] and Enum.all?(values, &(is_binary(&1) and &1 != ""))

  defp optional_strings?(nil), do: true
  defp optional_strings?(values), do: nonempty_strings?(values)

  defp optional_urls?(nil), do: true

  defp optional_urls?(values),
    do: is_list(values) and values != [] and Enum.all?(values, &valid_url?/1)

  defp optional_url(map, _key, nil), do: map

  defp optional_url(map, key, value), do: Map.put(map, key, value)

  defp valid_optional_urls?(opts) do
    Enum.all?([:registration_endpoint, :revocation_endpoint, :introspection_endpoint], fn key ->
      is_nil(opts[key]) or valid_url?(opts[key])
    end)
  end

  defp optional_list(map, _key, nil), do: map
  defp optional_list(map, key, value), do: Map.put(map, key, value)
end
