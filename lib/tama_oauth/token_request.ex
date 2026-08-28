defmodule TamaOAuth.TokenRequest do
  @moduledoc """
  Parses bounded authorization-code and refresh-token requests.

  This module validates transport-neutral fields. Applications still load and
  atomically consume the corresponding persisted credential.
  """

  alias TamaOAuth.{Error, PKCE}

  @assertion_type "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
  @max_client_id_bytes 2_048
  @max_credential_bytes 16_384
  @max_redirect_uri_bytes 2_048
  @max_scope_bytes 1_024

  @enforce_keys [:grant_type, :client_id, :authentication_method, :params]
  defstruct @enforce_keys

  @type authentication_method :: :none | :private_key_jwt
  @type t :: %__MODULE__{
          grant_type: :authorization_code | :refresh_token,
          client_id: String.t(),
          authentication_method: authentication_method(),
          params: map()
        }

  @spec parse(map(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def parse(params, opts \\ [])

  def parse(params, opts) when is_map(params) do
    headers = Keyword.get(opts, :authorization_headers, [])

    with :ok <- validate_client_id(params["client_id"]),
         {:ok, method} <- detect_authentication(params, headers),
         {:ok, grant_type} <- validate_grant(params) do
      {:ok,
       %__MODULE__{
         grant_type: grant_type,
         client_id: params["client_id"],
         authentication_method: method,
         params: params
       }}
    end
  end

  def parse(_params, _opts), do: invalid_request(:token_request)

  @spec detect_authentication(map(), list()) ::
          {:ok, authentication_method()} | {:error, Error.t()}
  def detect_authentication(params, authorization_headers)
      when is_map(params) and is_list(authorization_headers) do
    assertion? = Map.has_key?(params, "client_assertion")
    assertion_type? = Map.has_key?(params, "client_assertion_type")
    forbidden? = Map.has_key?(params, "client_secret") or authorization_headers != []

    case {assertion?, assertion_type?, forbidden?} do
      {false, false, false} ->
        {:ok, :none}

      {true, true, false} ->
        if params["client_assertion_type"] == @assertion_type,
          do: {:ok, :private_key_jwt},
          else: invalid_client(:method_detection)

      _ ->
        invalid_client(:method_detection)
    end
  end

  def detect_authentication(_params, _headers), do: invalid_client(:method_detection)

  defp validate_client_id(client_id) do
    if sized?(client_id, @max_client_id_bytes), do: :ok, else: invalid_request(:client_id)
  end

  defp validate_grant(%{"grant_type" => "authorization_code"} = params) do
    valid? =
      sized?(params["code"], @max_credential_bytes) and
        sized?(params["redirect_uri"], @max_redirect_uri_bytes) and
        PKCE.valid_verifier?(params["code_verifier"])

    if valid?, do: {:ok, :authorization_code}, else: invalid_request(:authorization_code)
  end

  defp validate_grant(%{"grant_type" => "refresh_token"} = params) do
    valid? =
      sized?(params["refresh_token"], @max_credential_bytes) and
        optional_sized?(params["scope"], @max_scope_bytes)

    if valid?, do: {:ok, :refresh_token}, else: invalid_request(:refresh_token)
  end

  defp validate_grant(%{"grant_type" => _unknown}),
    do: {:error, Error.new(:unsupported_grant_type, stage: :grant_type)}

  defp validate_grant(_params), do: invalid_request(:grant_type)

  defp sized?(value, max), do: is_binary(value) and byte_size(value) in 1..max
  defp optional_sized?(nil, _max), do: true
  defp optional_sized?(value, max), do: sized?(value, max)

  defp invalid_request(stage), do: {:error, Error.new(:invalid_request, stage: stage)}
  defp invalid_client(stage), do: {:error, Error.new(:invalid_client, stage: stage)}
end
