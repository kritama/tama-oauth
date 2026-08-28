defmodule TamaOAuth.Clock do
  @moduledoc "A clock behaviour for deterministic protocol tests."

  @callback now() :: DateTime.t()
end
