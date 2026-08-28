defmodule TamaOAuth.SystemClock do
  @moduledoc false
  @behaviour TamaOAuth.Clock

  @impl true
  def now, do: DateTime.utc_now()
end
