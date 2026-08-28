defmodule TamaOAuth.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    children = [
      {Task.Supervisor, name: TamaOAuth.TaskSupervisor}
    ]

    Supervisor.start_link(children,
      strategy: :one_for_one,
      name: TamaOAuth.Supervisor
    )
  end
end
