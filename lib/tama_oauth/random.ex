defmodule TamaOAuth.Random do
  @moduledoc "A cryptographically secure random-byte source behaviour."

  @callback bytes(pos_integer()) :: binary()
end
