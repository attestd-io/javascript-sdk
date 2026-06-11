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
  UNSUPPORTED,
} from '../src/testing.js';

function makeClient(fetchImpl: typeof globalThis.fetch, maxRetries = 0) {
  return new Client({
    apiKey: 'atst_test',
    fetch: fetchImpl,
    maxRetries,
    timeout: 5000,
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
  });

  it('parses PyTorch Lightning ShaiWorm compromise', async () => {
    const mock = new MockFetch(200, PYTORCH_LIGHTNING_COMPROMISED);
    const client = makeClient(mock.fn);
    const result = await client.check('pytorch-lightning', '2.6.3');
    expect(result.supplyChain!.compromised).toBe(true);
    expect(result.supplyChain!.malwareType).toBe('backdoor');
    expect(result.riskState).toBe('none');
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

describe('Client constructor', () => {
  it('throws AttestdError if apiKey is empty', () => {
    expect(() => new Client({ apiKey: '' })).toThrow(AttestdError);
  });

  it('throws AttestdError if apiKey is whitespace only', () => {
    expect(() => new Client({ apiKey: '   ' })).toThrow(AttestdError);
  });
});
