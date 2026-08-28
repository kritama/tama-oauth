defmodule TamaOAuth.Scope do
  @moduledoc """
  Normalizes space-delimited OAuth scopes against an explicit catalogue.
  """

  alias TamaOAuth.Error

  @default_max_bytes 1_024
  @scope_token ~r/\A[\x21\x23-\x5B\x5D-\x7E]+\z/

  @spec normalize(term(), [String.t()], keyword()) ::
          {:ok, String.t()} | {:error, Error.t()}
  def normalize(value, supported, opts \\ []) do
    max_bytes = Keyword.get(opts, :max_bytes, @default_max_bytes)

    with true <- valid_catalogue?(supported),
         true <- is_binary(value) and byte_size(value) in 1..max_bytes,
         requested when requested != [] <- value |> String.split(" ", trim: true) |> Enum.uniq(),
         true <- Enum.all?(requested, &valid_token?/1),
         true <- Enum.all?(requested, &(&1 in supported)) do
      {:ok, supported |> Enum.filter(&(&1 in requested)) |> serialize()}
    else
      _ -> {:error, Error.new(:invalid_scope, stage: :scope)}
    end
  end

  @spec parse(term(), [String.t()], keyword()) ::
          {:ok, [String.t()]} | {:error, Error.t()}
  def parse(value, supported, opts \\ []) do
    case normalize(value, supported, opts) do
      {:ok, normalized} -> {:ok, String.split(normalized)}
      error -> error
    end
  end

  @spec serialize([String.t()]) :: String.t()
  def serialize(scopes) when is_list(scopes), do: Enum.join(scopes, " ")

  defp valid_catalogue?(supported) do
    is_list(supported) and supported != [] and supported == Enum.uniq(supported) and
      Enum.all?(supported, &valid_token?/1)
  end

  defp valid_token?(value), do: is_binary(value) and String.match?(value, @scope_token)
end
