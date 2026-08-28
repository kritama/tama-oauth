defmodule TamaOAuth.Error do
  @moduledoc """
  A bounded OAuth protocol error independent of any HTTP framework.

  Applications translate this value into redirects or JSON responses at their
  transport boundary. `details` is internal safe metadata and is never included
  by `to_map/1`.
  """

  @code_atoms [
    :invalid_request,
    :invalid_client,
    :invalid_client_metadata,
    :invalid_redirect_uri,
    :invalid_grant,
    :invalid_target,
    :invalid_scope,
    :unsupported_grant_type,
    :temporarily_unavailable,
    :access_denied,
    :invalid_token,
    :insufficient_scope
  ]

  @type code ::
          :invalid_request
          | :invalid_client
          | :invalid_client_metadata
          | :invalid_redirect_uri
          | :invalid_grant
          | :invalid_target
          | :invalid_scope
          | :unsupported_grant_type
          | :temporarily_unavailable
          | :access_denied
          | :invalid_token
          | :insufficient_scope

  @type t :: %__MODULE__{
          code: code(),
          description: String.t() | nil,
          stage: atom() | nil,
          status: pos_integer(),
          details: map()
        }

  @enforce_keys [:code, :status]
  defexception [:code, :description, :stage, :status, details: %{}]

  @spec new(code(), keyword()) :: t()
  def new(code, opts \\ []) when code in @code_atoms do
    %__MODULE__{
      code: code,
      description: Keyword.get(opts, :description),
      stage: Keyword.get(opts, :stage),
      status: Keyword.get(opts, :status, default_status(code)),
      details: Keyword.get(opts, :details, %{})
    }
  end

  @spec to_map(t()) :: map()
  def to_map(%__MODULE__{} = error) do
    %{"error" => Atom.to_string(error.code)}
    |> maybe_put("error_description", error.description)
  end

  @impl true
  def message(%__MODULE__{code: code, description: nil}), do: Atom.to_string(code)

  def message(%__MODULE__{code: code, description: description}),
    do: "#{code}: #{description}"

  defp default_status(:invalid_client), do: 401
  defp default_status(:invalid_token), do: 401
  defp default_status(:insufficient_scope), do: 403
  defp default_status(:temporarily_unavailable), do: 503
  defp default_status(_code), do: 400

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)
end
