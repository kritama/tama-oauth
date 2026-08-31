# Architecture

TamaOAuth is a protocol library with application-supplied adapters. It owns
deterministic OAuth decisions and bounded parsing, but it does not own database
tables, application identities, lifecycle state, authorization policy, or HTTP
routes.

## Dependency direction

```text
Memovee adapters ─┐
                  ├─> TamaOAuth protocol core
Tama adapters ────┘
```

The core has no dependency on Memovee, Tama, Phoenix, Ecto, Ash, or Eventful.
Its public boundary uses package-owned structs and ordinary Elixir values; it
does not expose Joken or JOSE structs.

## Package responsibilities

| Area | Modules | Result owned by the application |
| --- | --- | --- |
| Request validation | `TamaOAuth.AuthorizationRequest`, `TamaOAuth.TokenRequest`, `TamaOAuth.Scope`, `TamaOAuth.PKCE`, `TamaOAuth.URI` | Client lookup, consent, code loading, and transactions |
| Client trust | `TamaOAuth.ClientMetadata`, `TamaOAuth.RemoteJSON`, `TamaOAuth.ClientRegistration` | Allowlist, cache, registrations, rate limits, and cleanup |
| Client authentication | `TamaOAuth.ClientAssertion`, `TamaOAuth.ClientAuthentication`, `TamaOAuth.SigningKey`, and the authentication method modules | Private-key custody, time, assertion identifiers, key retrieval, and durable assertion replay claims |
| Tokens and keys | `TamaOAuth.JWT`, `TamaOAuth.JWKS`, `TamaOAuth.Crypto` | Key custody, signing configuration, and access-token references |
| Lifecycle decisions | `TamaOAuth.RefreshToken`, `TamaOAuth.Introspection`, `TamaOAuth.Introspection.Client`, `TamaOAuth.Revocation` | Trusted introspection configuration, locks, persistence, Actor checks, and family revocation |
| Discovery | `TamaOAuth.Metadata.AuthorizationServer`, `TamaOAuth.Metadata.ProtectedResource` | Routes, configured identifiers, and HTTP caching |

## Authorization-server composition

Memovee supplies adapters for client lookup and caching, signing keys, assertion
replay storage, authorization-code consumption, grants, refresh-token families,
access-token references, consent, and Actor policy. It calls TamaOAuth for the
protocol decisions around those operations and applies the result within its
own Ecto/Eventful transaction.

In particular, `TamaOAuth.RefreshToken.evaluate/3` does not rotate a stored
credential. It returns either a rotation decision, a family-replay signal, or a
bounded OAuth error. Memovee must lock the relevant state and apply the result
atomically.

## Protected-resource composition

Tama supplies issuer, audience, scope, and trusted-key configuration. It uses
the protected-resource metadata builder and JWT/JWKS verification functions,
then constructs its own authenticated principal from the verified `{iss, sub}`
pair. `TamaOAuth.Introspection.Client` owns the bounded authenticated wire
exchange, while Tama selects the private key, endpoint, timeouts, and claim
bindings. Current Actor and grant policy remain with the authorization-server
application.

## Remote documents

`TamaOAuth.RemoteJSON` provides the shared network safety policy used for Client
ID Metadata Documents and JWKS:

- HTTPS by default, with explicit loopback development opt-in;
- DNS resolution before connection and address validation against private,
  loopback, link-local, documentation, multicast, and reserved ranges;
- connection pinning to a validated address while preserving the TLS hostname;
- same-origin enforcement where the calling protocol requires it;
- bounded redirects, response bodies, deadlines, and accepted media types; and
- injected resolver/requester functions for deterministic tests.

Applications still decide which client IDs are allowed, how long successful
documents are cached, and how failures are rate-limited.

## Adapter behaviours

- `TamaOAuth.Clock` and `TamaOAuth.Random` isolate nondeterminism.
- `TamaOAuth.ClientMetadata.Fetcher` permits controlled document retrieval.
- `TamaOAuth.KeyProvider` keeps key custody application-owned.
- `TamaOAuth.ReplayStore` defines the atomic assertion replay claim contract.

Small function callbacks accepted by authentication and fetch APIs are useful
for local composition and testing. Durable implementations belong in the
consuming application and should satisfy the corresponding behaviour where one
is defined.

## Failure model

Protocol validation fails closed. OAuth-facing failures use `TamaOAuth.Error`;
remote-document and key-set boundaries use small tagged atom errors. Internal
details may be attached to an error for application diagnostics, but
`TamaOAuth.Error.to_map/1` deliberately omits them from the protocol response.
