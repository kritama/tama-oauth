defmodule TamaOAuth.AuthorizationRequest do
  @moduledoc """
  Validates an OAuth authorization-code request before client lookup or consent.
  """

  alias TamaOAuth.{Error, PKCE, Scope}

  @default_limits %{
    client_id: 2_048,
    redirect_uri: 2_048,
    state: 1_024,
    scope: 1_024,
    resource: 2_048
  }

  @enforce_keys [
    :client_id,
    :redirect_uri,
    :resource,
    :scope,
    :state,
    :code_challenge
  ]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          client_id: String.t(),
          redirect_uri: String.t(),
          resource: String.t(),
          scope: String.t(),
          state: String.t(),
          code_challenge: String.t()
        }

  @spec validate(map(), keyword()) :: {:ok, t()} | {:error, Error.t()}
  def validate(params, opts) when is_map(params) and is_list(opts) do
    resource = Keyword.fetch!(opts, :resource)
    supported_scopes = Keyword.fetch!(opts, :supported_scopes)
    limits = Map.merge(@default_limits, Map.new(Keyword.get(opts, :limits, [])))

    with :ok <- validate_contract(params),
         :ok <- validate_sizes(params, limits),
         :ok <- validate_resource(params["resource"], resource),
         {:ok, scope} <- Scope.normalize(params["scope"], supported_scopes) do
      {:ok,
       %__MODULE__{
         client_id: params["client_id"],
         redirect_uri: params["redirect_uri"],
         resource: resource,
         scope: scope,
         state: params["state"],
         code_challenge: params["code_challenge"]
       }}
    end
  end

  def validate(_params, _opts),
    do: {:error, Error.new(:invalid_request, stage: :authorization_request)}

  defp validate_contract(params) do
    valid? =
      params["response_type"] == "code" and
        params["code_challenge_method"] == "S256" and
        PKCE.valid_challenge?(params["code_challenge"])

    if valid?, do: :ok, else: {:error, Error.new(:invalid_request, stage: :contract)}
  end

  defp validate_sizes(params, limits) do
    valid? =
      sized?(params["client_id"], limits.client_id) and
        sized?(params["redirect_uri"], limits.redirect_uri) and
        sized?(params["state"], limits.state) and sized?(params["scope"], limits.scope) and
        sized?(params["resource"], limits.resource)

    if valid?, do: :ok, else: {:error, Error.new(:invalid_request, stage: :bounds)}
  end

  defp validate_resource(actual, expected) when is_binary(expected) do
    if actual == expected,
      do: :ok,
      else: {:error, Error.new(:invalid_target, stage: :resource)}
  end

  defp sized?(value, max), do: is_binary(value) and byte_size(value) in 1..max
end
