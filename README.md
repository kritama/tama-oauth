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
- bounded `private_key_jwt` client-assertion minting;
- bounded authenticated token-introspection requests and response validation;
- protected-resource JWT verification, introspection, exact claim agreement,
  and canonical claim construction with application-supplied callbacks;
- asymmetric private signing-key decoding, normalization, and eligibility checks;
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

Public HTTPS origins are accepted by default. A deployment where a public peer
origin resolves to a private container-network address can opt in to only those
exact HTTPS origins under the `:tama_oauth` application:

```elixir
config :tama_oauth, TamaOAuth.RemoteJSON,
  trusted_private_origins: ["https://app.localhost"]
```

Trust entries are bounded and matched exactly by scheme, hostname, and effective
port. They may resolve to RFC1918 or IPv6 ULA addresses while DNS pinning and
normal certificate and hostname verification remain enabled. IP literals,
loopback, link-local, metadata, multicast, and other reserved addresses remain
blocked by this policy. Per-request `:trusted_private_origins` replaces the
application default when a caller needs narrower trust.

In a two-process Tama MCP App setup, configure each process independently: Tama
trusts only the provider origin (for example `https://app.localhost`) and the
provider trusts only the Tama origin (for example
`https://tama.app.localhost`). Docker service names and bridge addresses remain
private routing details, never OAuth identities.

Perform an authenticated introspection request while keeping trust policy,
time, the replay-resistant identifier, and private-key custody in the
application:

```elixir
{:ok, result} =
  TamaOAuth.Introspection.Client.introspect(
    incoming_access_token,
    endpoint: "https://memovee.example/auth/introspections",
    client_id: "tama-mcp-app",
    key: introspection_private_jwk,
    algorithm: "RS256",
    algorithms: ["RS256"],
    kid: "tama-introspection-1",
    jti: fresh_assertion_id,
    now: DateTime.utc_now() |> DateTime.to_unix(),
    ttl: 60,
    issuer: "https://memovee.example",
    audience: "https://tama.example/mcp/app",
    scopes: ["mcp.message"]
  )
```

Authenticate a protected-resource request while keeping key caching,
introspection credentials, rate limiting, and identity mapping in the
application:

```elixir
TamaOAuth.ProtectedResource.authenticate(incoming_access_token,
  issuer: "https://memovee.example",
  audience: "https://tama.example/mcp/app",
  scopes: ["mcp.message"],
  algorithms: ["RS256"],
  key_resolver: fn kid, algorithm -> cached_key(kid, algorithm) end,
  introspector: fn token, offline_claims ->
    with :ok <- allow_introspection(offline_claims["jti"]) do
      introspect(token)
    end
  end
)
```

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

## Releasing

TamaOAuth uses Git Flow with `develop` as the integration branch and `master`
as the production branch:

- `feature/*` branches start from `develop` and merge back into `develop`;
- `fix/*` branches start from `develop` and merge back into `develop`;
- `release/*` branches start from `develop`, contain only stabilization work,
  and merge into `master`; and
- `hotfix/*` branches start from `master` and merge directly into `master`.

Commits use the Conventional Commits format. The highest-impact commit reaching
`master` controls the next semantic version:

- `fix:` produces a patch release;
- `feat:` produces a minor release; and
- `feat!:`, `fix!:`, or a `BREAKING CHANGE:` footer produces a breaking
  release. Before `1.0.0`, breaking changes advance the minor version.

For a normal release:

1. Create `release/<planned-version>` from `develop` and perform final release
   fixes there.
2. Open a pull request from the release branch to `master`. Preserve the
   Conventional Commit history with a merge commit. If the pull request is
   squash-merged, its squash title must be a Conventional Commit containing the
   highest required release signal.
3. The merge into `master` makes Release Please open or update its generated
   release pull request with the next version and changelog.
4. Merge the generated release pull request. This creates the `vX.Y.Z` tag and
   GitHub release, reruns every package check from the tag, and publishes the
   package and documentation to Hex.
5. Merge `master` back into `develop`, then delete the release branch.

For an urgent production correction, create `hotfix/<slug>` from `master`, use
`fix:` commits, and merge it into `master`. Complete the generated patch release
pull request, then merge `master` back into `develop`.

The release configuration bootstraps the package at `0.1.0`; later releases use
the version recorded in the release manifest and the Conventional Commits
promoted to `master`. Only `master` can create tags or publish to Hex. CI
validates both protected branches and every pull request without publishing.

Before the first release, configure the repository as follows:

1. Create a GitHub environment named `hex`. Restrict deployments to the
   protected `master` branch, add required reviewers, prevent self-review, and
   disable administrator bypass where appropriate.
2. Save a dedicated, expiring Hex key with API write permission as the
   repository secret `HEX_API_KEY`. The protected `hex` environment still
   gates the publishing job before it can access the repository secret. Prefer
   an organization key over a personal key when publishing for a Hex
   organization.
3. Protect both `develop` and `master` and require the CI checks before
   merging.
4. Enable **Allow GitHub Actions to create and approve pull requests** under
   the organization and repository **Settings > Actions > General** pages.
   Release Please uses the short-lived `GITHUB_TOKEN`. Because events created
   by that token do not start new workflow runs, the release workflow explicitly
   dispatches CI for its generated pull request.

If Hex publication fails after the GitHub release exists, run the **Publish
Hex** workflow manually from `master` with that existing `vX.Y.Z` tag. Do not
create a new tag or change `mix.exs` for a retry.

## License

TamaOAuth is licensed under the [Apache License 2.0](LICENSE).
