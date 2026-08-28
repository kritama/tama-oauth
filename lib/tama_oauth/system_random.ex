defmodule TamaOAuth.SystemRandom do
  @moduledoc false
  @behaviour TamaOAuth.Random

  @impl true
  def bytes(count), do: :crypto.strong_rand_bytes(count)
end
