import { describe, it, expect, afterEach, vi } from 'vitest';
import { Client, VERSION } from '../src/index.js';
import { ResultCache } from '../src/cache.js';
import {
  MockFetch,
  SequentialMockFetch,
  NGINX_SAFE,
  NGINX_VULNERABLE,
} from '../src/testing.js';
import type { RiskResult } from '../src/models.js';

function sampleResult(overrides: Partial<RiskResult> = {}): RiskResult {
  return {
    product: 'nginx',
    version: '1.20.0',
    riskState: 'high',
    riskFactors: ['remote_code_execution'],
    activelyExploited: false,
    remoteExploitable: true,
    authenticationRequired: false,
    patchAvailable: true,
    fixedVersion: '1.27.4',
    confidence: 0.85,
    cveIds: ['CVE-2021-23017'],
    maxEpss: null,
    cves: [],
    lastUpdated: new Date('2024-06-01T12:00:00Z'),
    supplyChain: null,
    typosquat: null,
    ...overrides,
  };
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe('ResultCache', () => {
  it('runtime TTL expires after 300s', () => {
    const cache = new ResultCache('runtime');
    const result = sampleResult();
    cache.put('nginx', '1.20.0', result, 100_000);
    expect(cache.get('nginx', '1.20.0', 399_999)).not.toBeNull();
    expect(cache.get('nginx', '1.20.0', 400_000)).toBeNull();
  });

  it('development TTL is 24h', () => {
    const cache = new ResultCache('development');
    const result = sampleResult();
    cache.put('nginx', '1.20.0', result, 0);
    expect(cache.get('nginx', '1.20.0', 86_399_999)).not.toBeNull();
    expect(cache.get('nginx', '1.20.0', 86_400_000)).toBeNull();
  });

  it('ci policy never expires', () => {
    const cache = new ResultCache('ci');
    const result = sampleResult();
    cache.put('nginx', '1.20.0', result, 0);
    expect(cache.get('nginx', '1.20.0', 1e15)).not.toBeNull();
  });

  it('none policy always misses', () => {
    const cache = new ResultCache('none');
    cache.put('nginx', '1.20.0', sampleResult());
    expect(cache.get('nginx', '1.20.0')).toBeNull();
  });
});

describe('Client cache', () => {
  it('cache hit skips API call', async () => {
    const mock = new SequentialMockFetch([
      { statusCode: 200, body: NGINX_VULNERABLE },
      { statusCode: 200, body: NGINX_SAFE },
    ]);
    const client = new Client({
      apiKey: 'atst_test',
      fetch: mock.fn,
      maxRetries: 0,
      cachePolicy: 'runtime',
    });
    const first = await client.check('nginx', '1.20.0');
    const second = await client.check('nginx', '1.20.0');
    expect(first.riskState).toBe('high');
    expect(second.riskState).toBe('high');
    expect(mock.callCount).toBe(1);
    const stats = client.stats();
    expect(stats.apiCallsMade).toBe(1);
    expect(stats.cacheHits).toBe(1);
    expect(stats.callsSaved).toBe(1);
  });

  it('none policy always hits API', async () => {
    const mock = new SequentialMockFetch([
      { statusCode: 200, body: NGINX_VULNERABLE },
      { statusCode: 200, body: NGINX_SAFE },
    ]);
    const client = new Client({
      apiKey: 'atst_test',
      fetch: mock.fn,
      maxRetries: 0,
      cachePolicy: 'none',
    });
    await client.check('nginx', '1.20.0');
    const second = await client.check('nginx', '1.20.0');
    expect(mock.callCount).toBe(2);
    expect(second.riskState).toBe('none');
    expect(client.stats().cacheHits).toBe(0);
  });

  it('invalidateCache forces refetch', async () => {
    const mock = new SequentialMockFetch([
      { statusCode: 200, body: NGINX_VULNERABLE },
      { statusCode: 200, body: NGINX_SAFE },
    ]);
    const client = new Client({
      apiKey: 'atst_test',
      fetch: mock.fn,
      maxRetries: 0,
      cachePolicy: 'runtime',
    });
    await client.check('nginx', '1.20.0');
    client.invalidateCache('nginx', '1.20.0');
    const second = await client.check('nginx', '1.20.0');
    expect(mock.callCount).toBe(2);
    expect(second.riskState).toBe('none');
    expect(client.stats().apiCallsMade).toBe(2);
    expect(client.stats().cacheHits).toBe(0);
  });

  it('stats.callsSaved counts cache hits', async () => {
    const mock = new MockFetch(200, NGINX_VULNERABLE);
    const client = new Client({
      apiKey: 'atst_test',
      fetch: mock.fn,
      maxRetries: 0,
      cachePolicy: 'runtime',
    });
    await client.check('nginx', '1.20.0');
    await client.check('nginx', '1.20.0');
    await client.check('nginx', '1.20.0');
    const stats = client.stats();
    expect(stats.apiCallsMade).toBe(1);
    expect(stats.cacheHits).toBe(2);
    expect(stats.batchSaves).toBe(0);
    expect(stats.callsSaved).toBe(2);
  });

  it('checkBatch uses cache for repeated items', async () => {
    const batchBody = {
      results: [
        { product: 'nginx', version: '1.20.0', result: NGINX_VULNERABLE },
      ],
    };
    const mock = new SequentialMockFetch([{ statusCode: 200, body: batchBody }]);
    const client = new Client({
      apiKey: 'atst_test',
      fetch: mock.fn,
      maxRetries: 0,
      cachePolicy: 'runtime',
    });
    const first = await client.checkBatch([{ product: 'nginx', version: '1.20.0' }]);
    const second = await client.checkBatch([{ product: 'nginx', version: '1.20.0' }]);
    expect(first[0]?.riskState).toBe('high');
    expect(second[0]?.riskState).toBe('high');
    expect(mock.callCount).toBe(1);
    expect(client.stats().apiCallsMade).toBe(1);
    expect(client.stats().cacheHits).toBe(1);
  });

  it('package version is 0.8.0', () => {
    expect(VERSION).toBe('0.8.0');
  });
});
