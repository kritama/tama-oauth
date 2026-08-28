# Architecture

TamaOAuth is a protocol library with application-supplied adapters. It does not
own database tables, application identities, lifecycle state, or HTTP routes.

## Roles

### Authorization server

Memovee will compose the authorization-server protocol with adapters for:

- client lookup and Client ID Metadata Document persistence;
- authorization-code consumption;
- grant and consent policy;
- refresh-token family persistence and rotation;
- access-token references and introspection;
- asymmetric signing and public JWK publication;
- subject-to-Actor mapping.

### Resource server

Tama will compose the resource-server protocol with adapters for:

- issuer and audience configuration;
- cached JWKS retrieval;
- JWT verification;
- online introspection when current authorization state is required;
- Actor construction and scope enforcement.

## Dependency direction

```text
Memovee adapters ─┐
                  ├─> TamaOAuth protocol core
Tama adapters ────┘
```

The core must not depend on Memovee, Tama, Phoenix, Ecto, Ash, or Eventful.
Framework integrations may be added later as optional packages or thin modules
that depend on the core.

## Planned namespaces

- `TamaOAuth.AuthorizationServer`
- `TamaOAuth.ResourceServer`
- `TamaOAuth.Client`
- `TamaOAuth.Metadata`
- `TamaOAuth.PKCE`
- `TamaOAuth.Token`
- `TamaOAuth.JWKS`
- `TamaOAuth.Introspection`

These namespaces describe ownership areas, not committed APIs. Behaviours and
data structures will be introduced only as implementation slices require them.
