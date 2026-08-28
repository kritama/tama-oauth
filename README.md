# TamaOAuth

Backend-neutral OAuth 2.1 building blocks shared by Kritama applications.

`TamaOAuth` separates protocol mechanics from application policy and persistence.
Memovee can provide the authorization-server adapters while Tama can provide the
resource-server adapters without either application adopting the other's schemas,
web layer, or lifecycle model.

The package is pre-release. Its public API will be introduced incrementally and
may change before `1.0.0`.

## Design boundaries

The package will own reusable protocol behavior, including:

- authorization-code flow with PKCE;
- OAuth client metadata and authentication;
- authorization-server and protected-resource metadata;
- resource indicators, scopes, and OAuth error construction;
- access-token signing and verification contracts;
- refresh-token rotation and replay-detection rules;
- token introspection contracts.

Applications will continue to own:

- Ecto, Ash, or other persistence schemas and queries;
- Eventful lifecycle transitions;
- users, Actors, grants, and authorization policy;
- Phoenix controllers, routers, LiveViews, and consent UI;
- secrets and deployment configuration.

See [Architecture](docs/architecture.md) for the initial package boundary.

## Installation

Until the first Hex release, add the package by path during local development:

```elixir
def deps do
  [
    {:tama_oauth, path: "../tama-oauth"}
  ]
end
```

After publication, use `{:tama_oauth, "~> 0.1.0"}`.

## Development

Run the complete local check with:

```console
mix precommit
```

## License

TamaOAuth is licensed under the [Apache License 2.0](LICENSE).
