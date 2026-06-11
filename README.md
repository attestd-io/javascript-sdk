# attestd

Official JavaScript/TypeScript client for the [Attestd](https://attestd.io) security risk API.

Thin `fetch` wrapper with zero runtime dependencies. ESM and CommonJS builds. TypeScript types mirror the Python SDK in camelCase.

**Node >= 18 required** (uses native `fetch` and `AbortSignal.timeout`).

---

## Installation

```bash
npm install @attestd/sdk
```

---

## Quick start

```typescript
import { Client } from '@attestd/sdk';

const client = new Client({ apiKey: process.env.ATTESTD_API_KEY! });

const result = await client.check('nginx', '1.25.3');

console.log(result.riskState);        // 'high'
console.log(result.patchAvailable);   // true
console.log(result.fixedVersion);     // '1.26.0'
console.log(result.cveIds);           // ['CVE-2024-7347']
```

---

## CI/CD gate example

Block a deployment when a dependency is at critical or high risk:

```typescript
import { Client, AttestdUnsupportedProductError } from '@attestd/sdk';

const client = new Client({ apiKey: process.env.ATTESTD_API_KEY! });

async function assertSafe(product: string, version: string) {
  try {
    const result = await client.check(product, version);
    if (result.riskState === 'critical' || result.riskState === 'high') {
      console.error(`BLOCKED: ${product}@${version} risk_state=${result.riskState}`);
      process.exit(1);
    }
  } catch (err) {
    if (err instanceof AttestdUnsupportedProductError) {
      // Product not in Attestd coverage — skip or warn depending on policy.
      console.warn(`${product} is not covered by Attestd, skipping.`);
      return;
    }
    throw err;
  }
}

await assertSafe('nginx', process.env.NGINX_VERSION!);
```

---

## Supply chain check

Attestd monitors select **PyPI** and **npm** packages for known malicious publishes and registry signals. Pass the package name exactly as published; scoped npm names work as-is (`@scope/pkg` is URL-encoded by the client).

```typescript
import { Client } from '@attestd/sdk';

const client = new Client({ apiKey: process.env.ATTESTD_API_KEY! });

// PyPI supply chain
const pypi = await client.check('litellm', '1.82.7');
if (pypi.supplyChain?.compromised) {
  console.error('SUPPLY CHAIN ALERT:', pypi.supplyChain.description);
  console.error('Sources:', pypi.supplyChain.sources);
}

// npm supply chain (scoped package names supported)
const npm = await client.check('@bitwarden/cli', '2026.4.0');
if (npm.supplyChain?.compromised) {
  console.error('SUPPLY CHAIN ALERT:', npm.supplyChain.malwareType);
  console.error('Removed at:', npm.supplyChain.removedAt);
}
```

---

## Error handling

| Error class | When thrown |
|---|---|
| `AttestdAuthError` | 401 — invalid or missing API key |
| `AttestdRateLimitError` | 429 — rate limit exceeded. Check `.retryAfter` (seconds) |
| `AttestdUnsupportedProductError` | 404 — product not in Attestd coverage. Check `.product` and `.version` |
| `AttestdAPIError` | Unexpected HTTP status, malformed response, network failure, or timeout. `.statusCode` is 0 for transport errors |

All error classes extend `AttestdError`, which extends `Error`.

```typescript
import {
  Client,
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  AttestdAPIError,
  AttestdError,
} from '@attestd/sdk';

try {
  const result = await client.check('nginx', '1.25.3');
} catch (err) {
  if (err instanceof AttestdAuthError) {
    console.error('Check your ATTESTD_API_KEY');
  } else if (err instanceof AttestdRateLimitError) {
    console.error(`Rate limited. Retry after ${err.retryAfter ?? '?'}s`);
  } else if (err instanceof AttestdUnsupportedProductError) {
    console.warn(`${err.product}@${err.version} is not covered`);
  } else if (err instanceof AttestdAPIError) {
    console.error(`API error (status=${err.statusCode}): ${err.message}`);
  }
}
```

---

## Client options

```typescript
const client = new Client({
  apiKey: 'atst_...',      // required
  baseUrl: 'https://api.attestd.io',  // optional override
  timeout: 10_000,          // ms, default 10 000
  maxRetries: 3,            // retries on 5xx, default 3
  fetch: customFetch,       // inject for testing (see below)
  retryDelayMs: 1_000,      // base backoff delay, default 1 000 (set to 10 in tests)
});
```

---

## Testing module

Import mock helpers from `@attestd/sdk/testing`. They are not included in the main bundle.

```typescript
import { Client } from '@attestd/sdk';
import {
  MockFetch,
  SequentialMockFetch,
  NGINX_VULNERABLE,
  LITELLM_COMPROMISED,
  PYTORCH_LIGHTNING_COMPROMISED,
  BITWARDEN_CLI_SAFE,
  BITWARDEN_CLI_COMPROMISED,
} from '@attestd/sdk/testing';

// Single fixed response
const mock = new MockFetch(200, NGINX_VULNERABLE);
const client = new Client({ apiKey: 'test', fetch: mock.fn });
const result = await client.check('nginx', '1.25.3');
expect(result.riskState).toBe('high');
console.log(mock.callCount); // 1

// Sequential responses (useful for retry testing)
const seq = new SequentialMockFetch([
  { statusCode: 503, body: {} },
  { statusCode: 200, body: NGINX_VULNERABLE },
]);
const retryClient = new Client({ apiKey: 'test', fetch: seq.fn, maxRetries: 3 });
await retryClient.check('nginx', '1.25.3');
console.log(seq.callCount); // 2
```

**Available fixtures:** `NGINX_SAFE`, `NGINX_VULNERABLE`, `LOG4J_CRITICAL`, `UNSUPPORTED`, `LITELLM_SAFE`, `LITELLM_COMPROMISED`, `PYTORCH_LIGHTNING_COMPROMISED`, `BITWARDEN_CLI_SAFE`, `BITWARDEN_CLI_COMPROMISED`.

### Jest note

If you use Jest (< v29) with the `@attestd/sdk/testing` subpath, configure `customExportConditions`:

```js
// jest.config.js
module.exports = {
  testEnvironment: 'node',
  testEnvironmentOptions: {
    customExportConditions: ['node', 'require', 'default'],
  },
};
```

---

## Supported products

CVE-covered infrastructure products across databases, container runtimes, web/proxy, message brokers, and AI/ML frameworks. [Full product list](https://attestd.io/docs/products).

Supply chain monitoring covers **PyPI** and **npm**. [Monitored packages](https://attestd.io/docs/supply-chain).

---

## License

MIT
