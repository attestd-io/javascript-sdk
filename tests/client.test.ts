import { describe, it, expect } from 'vitest';
import { Client } from '../src/client.js';
import {
  AttestdError,
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  AttestdAPIError,
} from '../src/errors.js';
import {
  MockFetch,
  SequentialMockFetch,
  NGINX_SAFE,
  NGINX_VULNERABLE,
  LITELLM_COMPROMISED,
  PYTORCH_LIGHTNING_COMPROMISED,
  BITWARDEN_CLI_SAFE,
  BITWARDEN_CLI_COMPROMISED,
  LOG4J_CRITICAL,
  UNSUPPORTED,
} from '../src/testing.js';

function makeClient(fetchImpl: typeof globalThis.fetch, maxRetries = 0) {
  return new Client({
    apiKey: 'atst_test',
    fetch: fetchImpl,
    maxRetries,
    timeout: 5000,
    // Bypass cache so SequentialMockFetch call counts stay predictable.
    cachePolicy: 'none',
  });
}

describe('Client.check — happy path', () => {
  it('returns RiskResult with riskState none for safe nginx', async () => {
    const mock = new MockFetch(200, NGINX_SAFE);
    const client = makeClient(mock.fn);
    const result = await client.check('nginx', '1.26.1');
    expect(result.product).toBe('nginx');
    expect(result.riskState).toBe('none');
    expect(result.activelyExploited).toBe(false);
    expect(result.supplyChain).toBeNull();
    expect(result.lastUpdated).toBeInstanceOf(Date);
    expect(mock.callCount).toBe(1);
  });

  it('returns RiskResult with riskState high for vulnerable nginx', async () => {
    const mock = new MockFetch(200, NGINX_VULNERABLE);
    const client = makeClient(mock.fn);
    const result = await client.check('nginx', '1.25.3');
    expect(result.riskState).toBe('high');
    expect(result.patchAvailable).toBe(true);
    expect(result.fixedVersion).toBe('1.26.0');
    expect(result.cveIds).toContain('CVE-2024-7347');
  });
});

describe('Client.check — supply chain', () => {
  it('parses a compromised supply chain signal', async () => {
    const mock = new MockFetch(200, LITELLM_COMPROMISED);
    const client = makeClient(mock.fn);
    const result = await client.check('litellm', '1.57.3');
    expect(result.supplyChain).not.toBeNull();
    expect(result.supplyChain!.compromised).toBe(true);
    expect(result.supplyChain!.malwareType).toBe('credential_stealer');
    expect(result.supplyChain!.compromisedAt).toBeInstanceOf(Date);
    expect(result.supplyChain!.provenance).toBeNull();
  });

  it('parses PyTorch Lightning ShaiWorm compromise', async () => {
    const mock = new MockFetch(200, PYTORCH_LIGHTNING_COMPROMISED);
    const client = makeClient(mock.fn);
    const result = await client.check('pytorch-lightning', '2.6.3');
    expect(result.supplyChain!.compromised).toBe(true);
    expect(result.supplyChain!.malwareType).toBe('backdoor');
    expect(result.riskState).toBe('none');
  });

  it('parses provenance tri-state for npm packages', async () => {
    const mock = new MockFetch(200, BITWARDEN_CLI_SAFE);
    const client = makeClient(mock.fn);
    const result = await client.check('@bitwarden/cli', '2026.3.0');
    expect(result.supplyChain!.provenance).toBe(true);

    const drop = new MockFetch(200, BITWARDEN_CLI_COMPROMISED);
    const dropClient = makeClient(drop.fn);
    const dropped = await dropClient.check('@bitwarden/cli', '2026.4.0');
    expect(dropped.supplyChain!.provenance).toBe(false);
  });
});

describe('Client.check — error responses', () => {
  it('throws AttestdAuthError on 401', async () => {
    const mock = new MockFetch(401, { error: 'unauthorized' });
    const client = makeClient(mock.fn);
    await expect(client.check('nginx', '1.25.3')).rejects.toThrow(AttestdAuthError);
  });

  it('throws AttestdRateLimitError on 429 with retryAfter', async () => {
    const mock = new MockFetch(429, { error: 'rate_limit' }, { 'retry-after': '30' });
    const client = makeClient(mock.fn);
    try {
      await client.check('nginx', '1.25.3');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestdRateLimitError);
      expect((err as AttestdRateLimitError).retryAfter).toBe(30);
    }
  });

  it('throws AttestdUnsupportedProductError on 404', async () => {
    const mock = new MockFetch(404, { error: 'not found' });
    const client = makeClient(mock.fn);
    try {
      await client.check('unknown-thing', '1.0.0');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestdUnsupportedProductError);
      expect((err as AttestdUnsupportedProductError).product).toBe('unknown-thing');
      expect((err as AttestdUnsupportedProductError).version).toBe('1.0.0');
    }
  });

  it('throws AttestdUnsupportedProductError on HTTP 200 with supported false', async () => {
    const mock = new MockFetch(200, UNSUPPORTED);
    const client = makeClient(mock.fn);
    try {
      await client.check('unknown-thing', '1.0.0');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestdUnsupportedProductError);
      expect((err as AttestdUnsupportedProductError).product).toBe('unknown-thing');
      expect((err as AttestdUnsupportedProductError).version).toBe('1.0.0');
    }
  });

  it('attaches typosquat signal when unsupported product resembles known package', async () => {
    const mock = new MockFetch(200, {
      supported: false,
      typosquat: {
        detected: true,
        resembles: 'langchain',
        confidence: 0.92,
        ecosystem: 'pypi',
      },
    });
    const client = makeClient(mock.fn);
    try {
      await client.check('langchian', '1.0.0');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestdUnsupportedProductError);
      expect((err as AttestdUnsupportedProductError).typosquat).toEqual({
        detected: true,
        resembles: 'langchain',
        confidence: 0.92,
        ecosystem: 'pypi',
        kind: 'typosquat',
        likelyIntended: [],
      });
    }
  });

  it('attaches hallucination kind for AI-invented package names', async () => {
    const mock = new MockFetch(200, {
      supported: false,
      typosquat: {
        detected: true,
        kind: 'hallucination',
        resembles: 'jscodeshift',
        likely_intended: ['jscodeshift'],
        confidence: 0.9,
        ecosystem: 'npm',
      },
    });
    const client = makeClient(mock.fn);
    try {
      await client.check('react-codeshift', '1.0.0');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestdUnsupportedProductError);
      expect((err as AttestdUnsupportedProductError).typosquat).toEqual({
        detected: true,
        resembles: 'jscodeshift',
        confidence: 0.9,
        ecosystem: 'npm',
        kind: 'hallucination',
        likelyIntended: ['jscodeshift'],
      });
    }
  });

  it('parses Retry-After HTTP-date header on 429', async () => {
    const retryAt = new Date(Date.now() + 90_000).toUTCString();
    const mock = new MockFetch(429, { error: 'rate_limit' }, { 'retry-after': retryAt });
    const client = makeClient(mock.fn);
    try {
      await client.check('nginx', '1.25.3');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestdRateLimitError);
      const retryAfter = (err as AttestdRateLimitError).retryAfter;
      expect(retryAfter).not.toBeNull();
      expect(retryAfter!).toBeGreaterThanOrEqual(80);
      expect(retryAfter!).toBeLessThanOrEqual(95);
    }
  });

  it('throws AttestdAPIError on 500 after all retries exhausted', async () => {
    const seq = new SequentialMockFetch([
      { statusCode: 503, body: {} },
      { statusCode: 503, body: {} },
      { statusCode: 503, body: {} },
      { statusCode: 503, body: {} },
    ]);
    const client = new Client({
      apiKey: 'atst_test',
      fetch: seq.fn,
      maxRetries: 3,
      timeout: 5000,
      retryDelayMs: 10,
    });
    await expect(client.check('nginx', '1.25.3')).rejects.toThrow(AttestdAPIError);
    expect(seq.callCount).toBe(4);
  });

  it('retries on 503 and succeeds on second attempt', async () => {
    const seq = new SequentialMockFetch([
      { statusCode: 503, body: {} },
      { statusCode: 200, body: NGINX_SAFE },
    ]);
    const client = new Client({
      apiKey: 'atst_test',
      fetch: seq.fn,
      maxRetries: 3,
      timeout: 5000,
      retryDelayMs: 10,
    });
    const result = await client.check('nginx', '1.26.1');
    expect(result.riskState).toBe('none');
    expect(seq.callCount).toBe(2);
  });
});

describe('Client.check — network/transport errors', () => {
  it('throws AttestdAPIError with statusCode 0 on network failure', async () => {
    const failFetch: typeof globalThis.fetch = async () => {
      throw new TypeError('Failed to fetch');
    };
    const client = makeClient(failFetch, 0);
    try {
      await client.check('nginx', '1.25.3');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestdAPIError);
      expect((err as AttestdAPIError).statusCode).toBe(0);
    }
  });

  it('throws AttestdAPIError with statusCode 0 on timeout', async () => {
    const timeoutFetch: typeof globalThis.fetch = async () => {
      const err = new Error('The operation was aborted due to timeout');
      err.name = 'TimeoutError';
      throw err;
    };
    const client = makeClient(timeoutFetch, 0);
    try {
      await client.check('nginx', '1.25.3');
      expect.fail('should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(AttestdAPIError);
      expect((err as AttestdAPIError).statusCode).toBe(0);
      expect((err as AttestdAPIError).message).toContain('timed out');
    }
  });

  it('throws AttestdAPIError on malformed JSON body', async () => {
    const badJsonFetch: typeof globalThis.fetch = async () =>
      new Response('not json', {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    const client = makeClient(badJsonFetch);
    await expect(client.check('nginx', '1.25.3')).rejects.toMatchObject({
      name: 'AttestdAPIError',
      message: expect.stringMatching(/JSON/i),
    });
  });

  it('URL-encodes product and version query parameters', async () => {
    let capturedUrl = '';
    const captureFetch: typeof globalThis.fetch = async (input) => {
      capturedUrl = String(input);
      return new Response(JSON.stringify(NGINX_SAFE), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };
    const client = makeClient(captureFetch);
    await client.check('@bitwarden/cli', '2026.4.0');
    expect(capturedUrl).toContain('product=%40bitwarden%2Fcli');
    expect(capturedUrl).toContain('version=2026.4.0');
  });
});

describe('Client.checkBatch', () => {
  const BATCH_HAPPY = {
    results: [
      { product: 'nginx', version: '1.25.3', result: NGINX_VULNERABLE },
      { product: 'log4j', version: '2.14.1', result: LOG4J_CRITICAL },
    ],
  };

  const BATCH_MIXED = {
    results: [
      { product: 'nginx', version: '1.25.3', result: NGINX_VULNERABLE },
      { product: 'fake', version: '9.9.9', result: UNSUPPORTED },
    ],
  };

  it('returns two RiskResults on happy path', async () => {
    const mock = new MockFetch(200, BATCH_HAPPY);
    const client = makeClient(mock.fn);
    const results = await client.checkBatch([
      { product: 'nginx', version: '1.25.3' },
      { product: 'log4j', version: '2.14.1' },
    ]);
    expect(results).toHaveLength(2);
    expect(results[0]?.riskState).toBe('high');
    expect(results[1]?.riskState).toBe('critical');
    expect(mock.callCount).toBe(1);
  });

  it('returns null for unsupported items in a mixed batch', async () => {
    const mock = new MockFetch(200, BATCH_MIXED);
    const client = makeClient(mock.fn);
    const results = await client.checkBatch([
      { product: 'nginx', version: '1.25.3' },
      { product: 'fake', version: '9.9.9' },
    ]);
    expect(results[0]?.product).toBe('nginx');
    expect(results[1]).toBeNull();
  });

  it('returns empty array without calling fetch for empty input', async () => {
    const mock = new MockFetch(200, BATCH_HAPPY);
    const client = makeClient(mock.fn);
    const results = await client.checkBatch([]);
    expect(results).toEqual([]);
    expect(mock.callCount).toBe(0);
  });

  it('throws AttestdError when more than 100 items', async () => {
    const mock = new MockFetch(200, BATCH_HAPPY);
    const client = makeClient(mock.fn);
    const items = Array.from({ length: 101 }, (_, i) => ({
      product: `product-${i}`,
      version: '1.0.0',
    }));
    await expect(client.checkBatch(items)).rejects.toThrow(AttestdError);
    expect(mock.callCount).toBe(0);
  });

  it('throws AttestdRateLimitError on 429', async () => {
    const mock = new SequentialMockFetch([
      { statusCode: 429, body: {}, headers: { 'Retry-After': '60' } },
    ]);
    const client = makeClient(mock.fn);
    await expect(
      client.checkBatch([{ product: 'nginx', version: '1.25.3' }]),
    ).rejects.toThrow(AttestdRateLimitError);
    expect(mock.callCount).toBe(1);
  });
});

describe('Client constructor', () => {
  it('throws AttestdError if apiKey is empty', () => {
    expect(() => new Client({ apiKey: '' })).toThrow(AttestdError);
  });

  it('throws AttestdError if apiKey is whitespace only', () => {
    expect(() => new Client({ apiKey: '   ' })).toThrow(AttestdError);
  });

  it('reads apiKey from ATTESTD_API_KEY env when omitted', () => {
    const prev = process.env.ATTESTD_API_KEY;
    process.env.ATTESTD_API_KEY = 'atst_from_env';
    try {
      const client = new Client();
      expect(client).toBeInstanceOf(Client);
    } finally {
      if (prev === undefined) delete process.env.ATTESTD_API_KEY;
      else process.env.ATTESTD_API_KEY = prev;
    }
  });

  it('reads baseUrl from ATTESTD_BASE_URL env when omitted', async () => {
    const prevKey = process.env.ATTESTD_API_KEY;
    const prevBase = process.env.ATTESTD_BASE_URL;
    process.env.ATTESTD_API_KEY = 'atst_test';
    process.env.ATTESTD_BASE_URL = 'https://dev.api.attestd.io';

    let capturedUrl = '';
    const captureFetch: typeof globalThis.fetch = async (input) => {
      capturedUrl = String(input);
      return new Response(JSON.stringify(NGINX_SAFE), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      });
    };

    try {
      const client = new Client({ fetch: captureFetch });
      await client.check('nginx', '1.26.1');
      expect(capturedUrl).toMatch(/^https:\/\/dev\.api\.attestd\.io\/v1\/check/);
    } finally {
      if (prevKey === undefined) delete process.env.ATTESTD_API_KEY;
      else process.env.ATTESTD_API_KEY = prevKey;
      if (prevBase === undefined) delete process.env.ATTESTD_BASE_URL;
      else process.env.ATTESTD_BASE_URL = prevBase;
    }
  });
});
