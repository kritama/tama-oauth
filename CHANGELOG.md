# Changelog

## 0.1.0 (2026-08-28)

### Features

- Initial supervised Mix library.
- Hex package metadata, Apache-2.0 licensing, and multi-version CI with strict
  Credo and Dialyzer checks.
- Git Flow release and hotfix promotion, Conventional Commit release
  preparation, protected tag verification, and a gated GitHub Actions workflow
  for publishing packages and documentation to Hex.
- Backend-neutral authorization-server and protected-resource architecture.
- Bounded authorization, token, revocation, introspection, and Dynamic Client
  Registration request values.
- PKCE `S256`, exact resource and redirect handling, scope normalization, and
  package-owned OAuth errors.
- Client ID Metadata Document validation and SSRF-resistant `Req` retrieval.
- Public and `private_key_jwt` client authentication with assertion replay
  contracts.
- Asymmetric JWT access-token signing and verification plus public-only JWKS
  publication, retrieval, validation, and key selection.
- Refresh-token rotation and credential-family replay decisions.
- Authorization-server and protected-resource metadata builders.
- Injectable clock, random source, client metadata fetcher, key provider, and
  replay-store behaviours.
