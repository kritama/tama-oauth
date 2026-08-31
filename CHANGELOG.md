# Changelog

## [0.3.0](https://github.com/kritama/tama-oauth/compare/v0.2.1...v0.3.0) (2026-08-31)


### Features

* add protected resource authentication ([266de69](https://github.com/kritama/tama-oauth/commit/266de6950271ae4f0846bfd4ffea1c0fa3986b15))
* add protected resource authentication ([5fb2f9f](https://github.com/kritama/tama-oauth/commit/5fb2f9f153af7274702c79a906281f78fd70daf4))
* add protected resource authentication ([59955e9](https://github.com/kritama/tama-oauth/commit/59955e9906d1f44b704f96fe2e1b1eebf64ae925))


### Bug Fixes

* bound protected resource token headers ([91fe522](https://github.com/kritama/tama-oauth/commit/91fe522b9b0c9c4fcc6442bc1dd72c66bf9bae99))

## [0.2.1](https://github.com/kritama/tama-oauth/compare/v0.2.0...v0.2.1) (2026-08-31)


### Bug Fixes

* centralize introspection client mechanics ([682d1d5](https://github.com/kritama/tama-oauth/commit/682d1d58b1d28061ee74af6a307b31a5fbec1903))
* centralize introspection client mechanics ([f8e6d3e](https://github.com/kritama/tama-oauth/commit/f8e6d3e951c66592cc714df97881d5a30262fe65))
* centralize introspection client mechanics ([9885709](https://github.com/kritama/tama-oauth/commit/988570900b83a1f7ad7845ad0aee94c73a33d156))

## [0.2.0](https://github.com/kritama/tama-oauth/compare/v0.1.0...v0.2.0) (2026-08-31)


### Features

* mint private key client assertions ([1873500](https://github.com/kritama/tama-oauth/commit/18735006aba3f9a49eb6a9812fbcebbd97cb8390))


### Bug Fixes

* preserve configured assertion audience ([0b12f22](https://github.com/kritama/tama-oauth/commit/0b12f22414c5fd4af359ddd68739b1532d977505))

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
