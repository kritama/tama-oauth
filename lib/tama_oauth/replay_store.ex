defmodule TamaOAuth.ReplayStore do
  @moduledoc """
  Atomically claims a client-scoped assertion-ID digest until its acceptance
  window ends.
  """

  @callback claim(binary(), DateTime.t()) :: :ok | {:error, :replayed | :unavailable}
end
