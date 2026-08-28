defmodule TamaOAuth.ApplicationTest do
  use ExUnit.Case, async: true

  test "starts the library supervisor" do
    assert Process.whereis(TamaOAuth.Supervisor)
  end
end
