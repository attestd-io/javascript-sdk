# Changelog

All notable changes to `@attestd/sdk` are documented in this file.

## [0.8.1] - 2026-10-08

PATCH over published npm `0.8.0`. Covers unpublished `main` commits since tag `v0.8.0`. Additive `include=cves` is opt-in; public response shapes are otherwise unchanged.

### Added

- Opt-in `{ include: ['cves'] }` on `check()` and `checkBatch()` so `RiskResult.cves` is populated. Default requests stay compact. Compact and detailed results use separate cache keys. ([#3](https://github.com/attestd-io/javascript-sdk/pull/3))

### Fixed

- Reject empty or whitespace-only `cve()` ids locally with `AttestdError` (`attestd: cve_id is required`) instead of requesting `GET /v1/cve/` and treating the gateway 404 as "CVE not found". ([#9](https://github.com/attestd-io/javascript-sdk/pull/9))
- Map `products()`, `usage()`, and top-level `checkBatch()` HTTP 404s to `AttestdAPIError`. `check()` 404 and `supported: false` still raise `AttestdUnsupportedProductError`. ([#10](https://github.com/attestd-io/javascript-sdk/pull/10))
- Raise `AttestdAPIError` when a batch response `results` length does not match the request, instead of treating missing slots as outside coverage. ([#6](https://github.com/attestd-io/javascript-sdk/pull/6))
- Trim product and version on `check()` and `checkBatch()`, then throw `AttestdError` when either value is empty. ([#7](https://github.com/attestd-io/javascript-sdk/pull/7))
- Trim product and version on `invalidateCache()` so it matches `check()` cache keys and rejects whitespace-only values the same way. ([#8](https://github.com/attestd-io/javascript-sdk/pull/8))

### Documentation

- Document `maxEpss`, typosquat `kind` / `likelyIntended`, and cache APIs (`cachePolicy`, `stats()`, `invalidateCache()`). ([#2](https://github.com/attestd-io/javascript-sdk/pull/2))
- Match public copy and testing fixtures to API `risk_state` coupling: confirmed `supply_chain.compromised` is `critical`. ([#1](https://github.com/attestd-io/javascript-sdk/pull/1))
- Clarify that `SessionStats.batchSaves` stays 0 without async coalescing, so `callsSaved` equals `cacheHits`. ([#4](https://github.com/attestd-io/javascript-sdk/pull/4))
- Restore the `lastUpdated` README table row and document that `invalidateCache` drops both compact and detailed keys. ([#5](https://github.com/attestd-io/javascript-sdk/pull/5))

## [0.8.0] - 2026-07-29

Cache policies and session stats. First version recorded in this changelog.

[0.8.1]: https://github.com/attestd-io/javascript-sdk/compare/v0.8.0...v0.8.1
[0.8.0]: https://github.com/attestd-io/javascript-sdk/releases/tag/v0.8.0
