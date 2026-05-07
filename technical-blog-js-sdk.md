# Technical Briefing: Attestd JavaScript SDK (@attestd/sdk)

**For the writer. Not for publication as-is.**

---

## What shipped

`@attestd/sdk` version 0.1.0 is live on npm at https://www.npmjs.com/package/@attestd/sdk.

It is the official JavaScript/TypeScript client for the Attestd security risk API. It wraps `/v1/check` — the same endpoint the Python SDK wraps — and mirrors the Python SDK's field names in camelCase.

---

## The headline facts

- **Zero runtime dependencies.** The entire client is a typed wrapper around the native `fetch` API.
- **Node 18+.** Uses `fetch` and `AbortSignal.timeout()` — both standard in Node 18, no polyfill needed.
- **Dual ESM + CommonJS build.** Works in modern ESM projects, older CommonJS projects (bundled with tsup), and bundlers (webpack, Rollup, Vite, esbuild). `sideEffects: false` for tree-shaking.
- **Full TypeScript types.** `RiskResult`, `SupplyChainSignal`, `RiskState`, `RiskFactor` — all typed and exported. No `any`.
- **Subpath export for testing.** `@attestd/sdk/testing` ships `MockFetch`, `SequentialMockFetch`, and fixture bodies so callers can unit-test their own integration code without hitting the API.
- **Signed provenance.** The 0.1.0 tarball was built and signed via GitHub Actions with Sigstore provenance — the build is publicly verifiable at Sigstore's transparency log.

---

## Install

```bash
npm install @attestd/sdk
```

---

## Quick example

```typescript
import { Client } from '@attestd/sdk';

const client = new Client({ apiKey: process.env.ATTESTD_API_KEY });

const result = await client.check('nginx', '1.25.3');

console.log(result.riskState);       // 'high'
console.log(result.patchAvailable);  // true
console.log(result.fixedVersion);    // '1.26.0'
console.log(result.cveIds);          // ['CVE-2024-7347']
```

---

## Supply chain signal

The JS SDK surfaces the supply chain signal identically to the Python SDK. If a PyPI package version is compromised, `supplyChain.compromised` is `true` and `supplyChain.description` carries the threat summary:

```typescript
const result = await client.check('pytorch-lightning', '2.6.3');

if (result.supplyChain?.compromised) {
  console.error('SUPPLY CHAIN ALERT:', result.supplyChain.description);
  // SUPPLY CHAIN ALERT: ShaiWorm payload. Downloads Bun JS runtime on import...
}
```

Note: `riskState` can be `'none'` while `supply_chain.compromised` is `true`. These are two independent signals — a package can have no CVEs and still be malicious. The JS SDK preserves this distinction.

---

## Error model

Five typed error classes, all extending `AttestdError extends Error`:

| Class | Trigger |
|---|---|
| `AttestdAuthError` | 401 — bad or missing API key |
| `AttestdRateLimitError` | 429 — exposes `.retryAfter` in seconds |
| `AttestdUnsupportedProductError` | 404 — product not in coverage. Exposes `.product` and `.version` |
| `AttestdAPIError` | Unexpected HTTP status, malformed response, network failure, timeout. `.statusCode` is `0` for transport errors |
| `AttestdError` | Base class — catch-all for any Attestd error |

All error subclasses use `Object.setPrototypeOf` in their constructors — this is a JavaScript-specific fix required for `instanceof` to work correctly in transpiled CommonJS environments. Without it, `catch (err) { if (err instanceof AttestdRateLimitError)` silently fails. The Python SDK has no equivalent concern.

---

## Retry and timeout

- **Retries:** 3 retries on 5xx responses with exponential backoff (1s, 2s, 4s). 401 and 429 are surfaced immediately without retry.
- **Timeout:** 10 seconds per request via `AbortSignal.timeout()`. Timeouts throw `AttestdAPIError` with `statusCode: 0`.
- **Network failures:** Retried up to `maxRetries`, then thrown as `AttestdAPIError` with `statusCode: 0`.
- All defaults are overridable via `ClientOptions`.

---

## Testing module

The `@attestd/sdk/testing` subpath is a separate build entry — it is not included in the main bundle. Callers import it only in test files:

```typescript
import { Client } from '@attestd/sdk';
import { MockFetch, NGINX_VULNERABLE } from '@attestd/sdk/testing';

const mock = new MockFetch(200, NGINX_VULNERABLE);
const client = new Client({ apiKey: 'test', fetch: mock.fn });

const result = await client.check('nginx', '1.25.3');
// result.riskState === 'high'
// mock.callCount === 1
```

Fixture bodies included: `NGINX_SAFE`, `NGINX_VULNERABLE`, `LOG4J_CRITICAL`, `UNSUPPORTED`, `LITELLM_SAFE`, `LITELLM_COMPROMISED`, `PYTORCH_LIGHTNING_COMPROMISED`.

The Python SDK has `attestd.testing` with the same fixture philosophy.

---

## TypeScript type surface

```typescript
type RiskState = 'critical' | 'high' | 'elevated' | 'low' | 'none';

type RiskFactor =
  | 'active_exploitation'
  | 'remote_code_execution'
  | 'no_authentication_required'
  | 'internet_exposed_service'
  | 'patch_available';

interface SupplyChainSignal {
  compromised: boolean;
  sources: string[];
  malwareType: string | null;
  description: string | null;
  advisoryUrl: string | null;
  compromisedAt: Date | null;
  removedAt: Date | null;
}

interface RiskResult {
  product: string;
  version: string;
  riskState: RiskState;
  riskFactors: RiskFactor[];
  activelyExploited: boolean;
  remoteExploitable: boolean;
  authenticationRequired: boolean;
  patchAvailable: boolean;
  fixedVersion: string | null;
  confidence: number;
  cveIds: string[];
  lastUpdated: Date;
  supplyChain: SupplyChainSignal | null;
}
```

Field names are camelCase mirrors of the Python SDK's snake_case fields. `Date` fields are parsed from ISO strings at response time — callers get real `Date` objects, not strings.

---

## Repo and publishing

- **Repo:** https://github.com/attestd-io/javascript-sdk
- **npm:** https://www.npmjs.com/package/@attestd/sdk
- **Publishing:** GitHub Actions on `v*` tag push. Builds, tests, then publishes with `--provenance` flag (Sigstore-signed).
- **Version:** 0.1.0

---

## Angles for the writer

- **"Same API, same types, now in JavaScript"** — the Python SDK launched first; the JS SDK is a direct mirror. Developers who already use the Python SDK can pick up the JS types immediately.
- **Zero dependency angle** — most API clients ship with `axios`, `got`, or `node-fetch`. This one uses only the platform. Relevant for security-conscious teams auditing their dependency trees.
- **Testing module angle** — most SDKs make you mock at the HTTP level (nock, msw). Attestd ships typed fixture objects so you can test your gate logic against realistic responses without a network.
- **Provenance angle** — the SDK that helps you catch supply chain attacks is itself provenance-signed. The transparency log entry for 0.1.0 is publicly verifiable.
- **AI agent tooling angle** — the same `check()` call works as a deterministic tool in an LLM agent tool loop. TypeScript + strict types make it straightforward to wire into Vercel AI SDK, LangChain.js, or any tool-calling framework.

---

## What to avoid

- Do not describe it as a "full-featured SDK" — it wraps one endpoint (`/v1/check`). That is intentional, not a gap.
- Do not imply browser support as a primary use case — Node 18+ is the target. It will work in modern browsers but we are not publishing a browser bundle.
- Do not reference the version number in evergreen content — it will go stale.
