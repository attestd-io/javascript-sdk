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
    cache.put('nginx', '1.20.0', result, { now: 100_000 });
    expect(cache.get('nginx', '1.20.0', { now: 399_999 })).not.toBeNull();
    expect(cache.get('nginx', '1.20.0', { now: 400_000 })).toBeNull();
  });

  it('development TTL is 24h', () => {
    const cache = new ResultCache('development');
    const result = sampleResult();
    cache.put('nginx', '1.20.0', result, { now: 0 });
    expect(cache.get('nginx', '1.20.0', { now: 86_399_999 })).not.toBeNull();
    expect(cache.get('nginx', '1.20.0', { now: 86_400_000 })).toBeNull();
  });

  it('ci policy never expires', () => {
    const cache = new ResultCache('ci');
    const result = sampleResult();
    cache.put('nginx', '1.20.0', result, { now: 0 });
    expect(cache.get('nginx', '1.20.0', { now: 1e15 })).not.toBeNull();
  });

  it('compact and detailed include=cves cache entries do not mix', () => {
    const cache = new ResultCache('ci');
    const compact = sampleResult({ cves: [] });
    const detailed = sampleResult({
      cves: [
        {
          cveId: 'CVE-2021-23017',
          cvssScore: 7.7,
          activelyExploited: false,
          remoteExploitable: true,
          epssScore: 0.12,
          epssPercentile: 0.8,
        },
      ],
    });
    cache.put('nginx', '1.20.0', compact);
    cache.put('nginx', '1.20.0', detailed, { includeCves: true });
    expect(cache.get('nginx', '1.20.0')?.cves).toEqual([]);
    expect(cache.get('nginx', '1.20.0', { includeCves: true })?.cves).toHaveLength(1);
  });

  it('invalidate drops both compact and detailed entries', () => {
    const cache = new ResultCache('ci');
    cache.put('nginx', '1.20.0', sampleResult());
    cache.put('nginx', '1.20.0', sampleResult(), { includeCves: true });
    cache.invalidate('nginx', '1.20.0');
    expect(cache.get('nginx', '1.20.0')).toBeNull();
    expect(cache.get('nginx', '1.20.0', { includeCves: true })).toBeNull();
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

  it('compact cache hit is not returned for include=cves', async () => {
    const detailed = {
      ...NGINX_VULNERABLE,
      cves: [
        {
          cve_id: 'CVE-2024-7347',
          cvss_score: 7.5,
          actively_exploited: false,
          remote_exploitable: true,
          epss_score: 0.12,
          epss_percentile: 0.8,
        },
      ],
    };
    const mock = new SequentialMockFetch([
      { statusCode: 200, body: NGINX_VULNERABLE },
      { statusCode: 200, body: detailed },
    ]);
    const client = new Client({
      apiKey: 'atst_test',
      fetch: mock.fn,
      maxRetries: 0,
      cachePolicy: 'runtime',
    });
    const compact = await client.check('nginx', '1.25.3');
    const withCves = await client.check('nginx', '1.25.3', { include: ['cves'] });
    expect(compact.cves).toEqual([]);
    expect(withCves.cves).toHaveLength(1);
    expect(withCves.cves[0]?.cveId).toBe('CVE-2024-7347');
    expect(mock.callCount).toBe(2);
  });

  it('package version is 0.8.0', () => {
    expect(VERSION).toBe('0.8.0');
  });
});
