# TamaOAuth

Framework-neutral OAuth and MCP authorization primitives shared by Kritama
applications.

`TamaOAuth` keeps protocol mechanics in one package while Memovee and Tama keep
their own persistence, identities, policy, and web layers. It supports both
sides of the planned integration: Memovee composes the authorization-server
functions and Tama composes the protected-resource functions.

The package is pre-release. Its public API may change before `1.0.0`.

## Included

- bounded authorization-code and refresh-token request parsing;
- PKCE `S256`, exact resource binding, redirect matching, and scope handling;
- OAuth protocol errors, including Dynamic Client Registration errors;
- authorization-server and protected-resource metadata builders;
- Client ID Metadata Document validation and SSRF-resistant retrieval;
- public-client and `private_key_jwt` authentication with replay callbacks;
- asymmetric JWT access-token signing and verification;
- public-only JWKS publication, retrieval, validation, and key selection;
- refresh-token rotation and family-replay decisions;
- revocation and introspection request/response values;
- bounded public-client Dynamic Client Registration normalization; and
- behaviours for clocks, randomness, fetchers, replay stores, and key providers.

The package deliberately has no Phoenix, Ecto, Ash, Eventful, Memovee, or Tama
dependency. Applications remain responsible for database transactions,
authorization policy, consent, lifecycle state, HTTP rendering, caching, rate
limits, configuration, and secret storage.

See [Architecture](docs/architecture.md) for the complete boundary.

## Installation

Until the first Hex release, use a sibling path only for local development:

```elixir
def deps do
  [
    {:tama_oauth, path: "../tama-oauth"}
  ]
end
```

After publication:

```elixir
{:tama_oauth, "~> 0.1.0"}
```

## Examples

Validate the protocol portion of an authorization request before applying
application-owned client and consent policy:

```elixir
params = %{
  "response_type" => "code",
  "client_id" => "https://client.example/client.json",
  "redirect_uri" => "https://client.example/callback",
  "resource" => "https://tama.example/mcp/app",
  "scope" => "mcp.message",
  "state" => "opaque-client-state",
  "code_challenge" => "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
  "code_challenge_method" => "S256"
}

TamaOAuth.AuthorizationRequest.validate(params,
  resource: "https://tama.example/mcp/app",
  supported_scopes: ["mcp.message"]
)
```

Publish only public key material and verify an audience-bound access token:

```elixir
{:ok, jwks} = TamaOAuth.JWKS.public_document(application_signing_keys)

TamaOAuth.JWT.verify_access_token(token, jwks,
  issuer: "https://memovee.example",
  audience: "https://tama.example/mcp/app",
  scopes: ["mcp.message"]
)
```

For remote Client ID Metadata Documents, `TamaOAuth.ClientMetadata.fetch/2`
uses the package's bounded `Req` fetcher by default. Production applications
must still apply their own client-ID allowlist and cache the validated result.

## Integration rule

Library functions return package structs, ordinary maps, tagged tuples, or
`TamaOAuth.Error`. An application should translate those values at its HTTP and
persistence boundaries. It should atomically apply refresh decisions and replay
claims inside its own transaction rather than treating this package as a data
store.

## Development

Run the regular local check with:

```console
mix precommit
```

`mix precommit` checks formatting, warnings-as-errors compilation, Credo in
strict mode, and the test suite. Run the static type analysis separately after
building its PLT:

```console
mix dialyzer --plt
mix dialyzer --no-check
```

Validate generated documentation and package contents with:

```console
mix docs
mix hex.build
```

## License

TamaOAuth is licensed under the [Apache License 2.0](LICENSE).
