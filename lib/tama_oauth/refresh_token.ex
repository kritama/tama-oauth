defmodule TamaOAuth.RefreshToken do
  @moduledoc """
  Computes refresh-token rotation and replay decisions without persistence.

  Applications lock the grant and credential, call `evaluate/3`, then apply the
  returned decision atomically. A rotated token presented again always requests
  family revocation.
  """

  alias TamaOAuth.Error

  defmodule State do
    @moduledoc "Application-supplied persisted refresh-token state."
    @enforce_keys [:id, :family_id, :generation, :status, :issued_at]
    defstruct @enforce_keys ++ [:expires_at, :last_used_at]

    @type t :: %__MODULE__{}
  end

  defmodule Decision do
    @moduledoc "A persistence-neutral refresh rotation decision."
    @enforce_keys [:family_id, :invalidate_token_id, :next_generation]
    defstruct @enforce_keys

    @type t :: %__MODULE__{}
  end

  @type status :: :active | :rotated | :revoked
  @type state :: %State{
          id: term(),
          family_id: term(),
          generation: non_neg_integer(),
          status: status(),
          issued_at: DateTime.t(),
          expires_at: DateTime.t() | nil,
          last_used_at: DateTime.t() | nil
        }

  @spec evaluate(state(), DateTime.t(), keyword()) ::
          {:ok, Decision.t()}
          | {:replay, term()}
          | {:error, Error.t()}
  def evaluate(%State{status: :rotated, family_id: family_id}, %DateTime{}, _opts),
    do: {:replay, family_id}

  def evaluate(%State{status: :revoked}, %DateTime{}, _opts),
    do: invalid_grant(:refresh_revoked)

  def evaluate(%State{status: :active} = state, %DateTime{} = now, opts) do
    idle_lifetime = Keyword.get(opts, :idle_lifetime_seconds)

    with :ok <- validate_generation(state.generation),
         :ok <- validate_absolute_expiry(state.expires_at, now),
         :ok <- validate_idle_expiry(state, now, idle_lifetime) do
      {:ok,
       %Decision{
         family_id: state.family_id,
         invalidate_token_id: state.id,
         next_generation: state.generation + 1
       }}
    end
  end

  def evaluate(_state, _now, _opts), do: invalid_grant(:refresh_state)

  defp validate_generation(generation) when is_integer(generation) and generation >= 0, do: :ok
  defp validate_generation(_generation), do: invalid_grant(:refresh_generation)

  defp validate_absolute_expiry(nil, _now), do: :ok

  defp validate_absolute_expiry(%DateTime{} = expires_at, now) do
    if DateTime.compare(expires_at, now) == :gt,
      do: :ok,
      else: invalid_grant(:refresh_expired)
  end

  defp validate_absolute_expiry(_expires_at, _now), do: invalid_grant(:refresh_expired)

  defp validate_idle_expiry(_state, _now, nil), do: :ok

  defp validate_idle_expiry(state, now, seconds)
       when is_integer(seconds) and seconds > 0 do
    last_used_at = state.last_used_at || state.issued_at
    cutoff = DateTime.add(now, -seconds, :second)

    if match?(%DateTime{}, last_used_at) and DateTime.compare(last_used_at, cutoff) == :gt,
      do: :ok,
      else: invalid_grant(:refresh_idle_expired)
  end

  defp validate_idle_expiry(_state, _now, _seconds), do: invalid_grant(:refresh_idle_expired)

  defp invalid_grant(stage), do: {:error, Error.new(:invalid_grant, stage: stage)}
end
