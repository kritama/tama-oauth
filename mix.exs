defmodule TamaOAuth.MixProject do
  use Mix.Project

  @version "0.4.1"
  @source_url "https://github.com/kritama/tama-oauth"

  def project do
    [
      app: :tama_oauth,
      version: @version,
      elixir: "~> 1.17",
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      source_url: @source_url,
      homepage_url: @source_url,
      package: package(),
      docs: docs(),
      dialyzer: dialyzer(),
      aliases: aliases()
    ]
  end

  def application do
    [
      extra_applications: [:logger],
      mod: {TamaOAuth.Application, []}
    ]
  end

  def cli do
    [preferred_envs: [precommit: :test]]
  end

  defp description do
    "Backend-neutral OAuth 2.1 and MCP authorization primitives for Elixir applications."
  end

  defp dialyzer do
    [
      plt_core_path: "priv/plts",
      plt_add_apps: [:ex_unit, :mix],
      plt_file: {:no_warn, "priv/plts/dialyzer.plt"}
    ]
  end

  defp package do
    [
      files: ~w(lib docs .formatter.exs mix.exs README.md CHANGELOG.md LICENSE),
      licenses: ["Apache-2.0"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md", "LICENSE", "docs/architecture.md"],
      groups_for_modules: [
        "Requests and values": [
          TamaOAuth.AuthorizationRequest,
          TamaOAuth.ClientRegistration,
          TamaOAuth.Error,
          TamaOAuth.Introspection,
          TamaOAuth.Introspection.Client,
          TamaOAuth.PKCE,
          TamaOAuth.RefreshToken,
          TamaOAuth.Revocation,
          TamaOAuth.Scope,
          TamaOAuth.TokenRequest,
          TamaOAuth.URI
        ],
        "Client trust": [
          TamaOAuth.ClientAssertion,
          TamaOAuth.ClientAuthentication,
          TamaOAuth.ClientAuthentication.None,
          TamaOAuth.ClientAuthentication.PrivateKeyJWT,
          TamaOAuth.ClientMetadata,
          TamaOAuth.RemoteJSON,
          TamaOAuth.SigningKey
        ],
        "Tokens and discovery": [
          TamaOAuth.Crypto,
          TamaOAuth.JWT,
          TamaOAuth.JWKS,
          TamaOAuth.ProtectedResource,
          TamaOAuth.Metadata.AuthorizationServer,
          TamaOAuth.Metadata.ProtectedResource
        ],
        "Adapter behaviours": [
          TamaOAuth.ClientMetadata.Fetcher,
          TamaOAuth.Clock,
          TamaOAuth.KeyProvider,
          TamaOAuth.Random,
          TamaOAuth.ReplayStore
        ]
      ]
    ]
  end

  defp deps do
    [
      {:jason, "~> 1.4"},
      {:joken, "~> 2.6"},
      {:req, "~> 0.6"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:dialyxir, "~> 1.4", only: [:dev, :test], runtime: false},
      {:ex_doc, "~> 0.40", only: :dev, runtime: false}
    ]
  end

  defp aliases do
    [
      precommit: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "test"
      ]
    ]
  end
end
