# @attestd/sdk

[![npm version](https://img.shields.io/npm/v/@attestd/sdk)](https://www.npmjs.com/package/@attestd/sdk)

> Attestd checks whether a dependency version has exploitable CVEs or a confirmed supply-chain compromise. One API call returns a structured risk response.

[Get a free API key](https://api.attestd.io/portal/login) · [Full docs](https://attestd.io/docs)

Node 18+ required (native `fetch` and `AbortSignal.timeout`).

## Install

```bash
npm install @attestd/sdk
```

## Quick start

```typescript
import { Client } from '@attestd/sdk';

const client = new Client({ apiKey: process.env.ATTESTD_API_KEY! });
const result = await client.check('nginx', '1.25.3');
console.log(result.riskState);  // 'high'
console.log(result.cveIds);     // ['CVE-2024-7347']
```

## Batch check

Check up to 100 packages in one request. Each item costs one API call. A 429 is returned before billing if the batch would exceed your quota.

```typescript
const results = await client.checkBatch([
  { product: 'litellm', version: '1.82.7' },
  { product: 'nginx', version: '1.25.3' },
]);
// results[i] is RiskResult | null — null means outside coverage
```

Unsupported items return `null` rather than throwing. Typosquat signals are not surfaced on batch unsupported items.

## Supply chain check

Attestd monitors select PyPI and npm packages for known malicious publishes. Pass scoped npm names as-is (`@scope/pkg` is URL-encoded by the client).

```typescript
import { Client } from '@attestd/sdk';

const client = new Client({ apiKey: process.env.ATTESTD_API_KEY! });

const pypi = await client.check('litellm', '1.82.7');
console.log(pypi.supplyChain?.compromised);  // true

const npm = await client.check('@bitwarden/cli', '2026.4.0');
console.log(npm.supplyChain?.compromised);   // true
```

## Error handling

`AttestdUnsupportedProductError` means the product is outside Attestd coverage. That is unknown risk, not a safety signal.

```typescript
import { Client, AttestdUnsupportedProductError } from '@attestd/sdk';

const client = new Client({ apiKey: process.env.ATTESTD_API_KEY! });

try {
  await client.check(product, version);
} catch (err) {
  if (err instanceof AttestdUnsupportedProductError) {
    throw new Error(`${err.product} is outside Attestd coverage`);
  }
  throw err;
}
```

| Error class | When thrown |
|---|---|
| `AttestdAuthError` | 401, invalid or missing API key |
| `AttestdRateLimitError` | 429, rate limit exceeded. Check `.retryAfter` (seconds) |
| `AttestdUnsupportedProductError` | Product not in Attestd coverage (404 or 200 with `supported: false`). Check `.product`, `.version`, and `.typosquat` |
| `AttestdAPIError` | Unexpected HTTP status, malformed response, network failure, or timeout. `.statusCode` is 0 for transport errors |

All error classes extend `AttestdError`, which extends `Error`.

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
      console.warn(`${product} is not covered by Attestd, skipping.`);
      return;
    }
    throw err;
  }
}

await assertSafe('nginx', process.env.NGINX_VERSION!);
```

## Client options

```typescript
const client = new Client({
  apiKey: process.env.ATTESTD_API_KEY!,
  baseUrl: process.env.ATTESTD_BASE_URL ?? 'https://api.attestd.io',
  timeout: 10_000,
  maxRetries: 3,
  fetch: customFetch,
  retryDelayMs: 1_000,
});
```

Set `ATTESTD_API_KEY` and optionally `ATTESTD_BASE_URL` in the environment. The constructor reads both when options are omitted.

## RiskResult fields

| Field | Type | Description |
|---|---|---|
| `product` | `string` | Product name |
| `version` | `string` | Version queried |
| `riskState` | `RiskState` | `critical`, `high`, `elevated`, `low`, or `none` |
| `riskFactors` | `RiskFactor[]` | Machine-readable factors |
| `activelyExploited` | `boolean` | On the CISA KEV list |
| `remoteExploitable` | `boolean` | Remotely exploitable |
| `authenticationRequired` | `boolean` | True only if all CVEs require auth |
| `patchAvailable` | `boolean` | A fixed version is known |
| `fixedVersion` | `string \| null` | Earliest clean version |
| `confidence` | `number` | Synthesis confidence (0.0–1.0) |
| `cveIds` | `string[]` | CVE IDs in this assessment |
| `lastUpdated` | `Date` | UTC timestamp of last synthesis |
| `supplyChain` | `SupplyChainSignal \| null` | PyPI/npm signal when monitored |
| `typosquat` | `TyposquatSignal \| null` | Present when the name resembles a known product |

**SupplyChainSignal:** `compromised`, `sources`, `malwareType`, `description`, `advisoryUrl`, `compromisedAt`, `removedAt`

**TyposquatSignal:** `detected`, `resembles`, `confidence`, `ecosystem`

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

const mock = new MockFetch(200, NGINX_VULNERABLE);
const client = new Client({ apiKey: 'test', fetch: mock.fn });
const result = await client.check('nginx', '1.25.3');
expect(result.riskState).toBe('high');
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

## Supported products

CVE-covered infrastructure products across databases, container runtimes, web/proxy, message brokers, and AI/ML frameworks. [Full product list](https://attestd.io/docs/products).

Supply chain monitoring covers PyPI and npm. [Monitored packages](https://attestd.io/docs/supply-chain).

## License

MIT
