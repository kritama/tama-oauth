# Changelog

## 0.1.0 (2026-08-28)


### Features

* prepare initial Hex release ([6dfe39a](https://github.com/kritama/tama-oauth/commit/6dfe39a39bb4191cc0023dca2ae302d282903128))
* release TamaOAuth 0.1.0 ([a9b67ce](https://github.com/kritama/tama-oauth/commit/a9b67ce74a36939a0fbeb061fc3760c3da03e1e4))


### Bug Fixes

* **ci:** use GitHub token for release automation ([7c99e63](https://github.com/kritama/tama-oauth/commit/7c99e634da086fd8593b8ce9d58afa3a743b7711))
* **release:** bootstrap version 0.1.0 ([1ed1435](https://github.com/kritama/tama-oauth/commit/1ed1435337e4859a7367ca3c29fba5b52d94c768))
* **release:** bootstrap version 0.1.0 ([2ab877d](https://github.com/kritama/tama-oauth/commit/2ab877d50866c65e5e55d4c3e317653cdae1e348))

## Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## Unreleased

### Added

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
