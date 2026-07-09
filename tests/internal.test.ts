import { describe, it, expect } from 'vitest';
import { parseCheckResponse, parseRetryAfter, parseBatchCheckResponse } from '../src/internal.js';
import { AttestdAPIError } from '../src/errors.js';
import { NGINX_VULNERABLE, LOG4J_CRITICAL, UNSUPPORTED } from '../src/testing.js';

describe('parseCheckResponse', () => {
  it('rejects invalid risk_state values', () => {
    expect(() =>
      parseCheckResponse({ ...NGINX_VULNERABLE, risk_state: 'unknown' }, 'nginx', '1.25.3'),
    ).toThrow(AttestdAPIError);
  });

  it('filters unknown risk_factors', () => {
    const result = parseCheckResponse(
      {
        ...NGINX_VULNERABLE,
        risk_factors: ['remote_code_execution', 'bogus_factor'],
      },
      'nginx',
      '1.25.3',
    );
    expect(result.riskFactors).toEqual(['remote_code_execution']);
  });

  it('throws when last_updated is missing', () => {
    const { last_updated: _removed, ...body } = NGINX_VULNERABLE;
    expect(() => parseCheckResponse(body, 'nginx', '1.25.3')).toThrow(AttestdAPIError);
  });

  it('throws when supported is missing', () => {
    const { supported: _removed, ...body } = NGINX_VULNERABLE;
    expect(() => parseCheckResponse(body, 'nginx', '1.25.3')).toThrow(AttestdAPIError);
  });

  it('throws on invalid supply_chain timestamp', () => {
    expect(() =>
      parseCheckResponse(
        {
          ...NGINX_VULNERABLE,
          supply_chain: {
            compromised: true,
            sources: ['osv'],
            compromised_at: 'not-a-date',
          },
        },
        'langchain',
        '0.1.0',
      ),
    ).toThrow(AttestdAPIError);
  });

  it('parses maxEpss and cves with EPSS fields', () => {
    const result = parseCheckResponse(
      {
        ...NGINX_VULNERABLE,
        max_epss: 0.9401,
        cves: [
          {
            cve_id: 'CVE-2024-7347',
            cvss_score: 7.5,
            actively_exploited: false,
            remote_exploitable: true,
            epss_score: 0.9401,
            epss_percentile: 0.99,
          },
        ],
      },
      'nginx',
      '1.25.3',
    );
    expect(result.maxEpss).toBe(0.9401);
    expect(result.cves).toEqual([
      {
        cveId: 'CVE-2024-7347',
        cvssScore: 7.5,
        activelyExploited: false,
        remoteExploitable: true,
        epssScore: 0.9401,
        epssPercentile: 0.99,
      },
    ]);
  });

  it('returns null maxEpss and empty cves when absent', () => {
    const result = parseCheckResponse(NGINX_VULNERABLE, 'nginx', '1.25.3');
    expect(result.maxEpss).toBeNull();
    expect(result.cves).toEqual([]);
  });

  it('parses typosquat on supported responses', () => {
    const result = parseCheckResponse(
      {
        ...NGINX_VULNERABLE,
        typosquat: {
          detected: true,
          resembles: 'langchain',
          confidence: 0.9,
          ecosystem: 'pypi',
        },
      },
      'langchian',
      '1.0.0',
    );
    expect(result.typosquat).toEqual({
      detected: true,
      resembles: 'langchain',
      confidence: 0.9,
      ecosystem: 'pypi',
      kind: 'typosquat',
      likelyIntended: [],
    });
  });
});

describe('parseBatchCheckResponse', () => {
  it('returns RiskResult array when all items are supported', () => {
    const results = parseBatchCheckResponse(
      {
        results: [
          { product: 'nginx', version: '1.25.3', result: NGINX_VULNERABLE },
          { product: 'log4j', version: '2.14.1', result: LOG4J_CRITICAL },
        ],
      },
      [
        { product: 'nginx', version: '1.25.3' },
        { product: 'log4j', version: '2.14.1' },
      ],
    );
    expect(results).toHaveLength(2);
    expect(results[0]?.riskState).toBe('high');
    expect(results[1]?.riskState).toBe('critical');
  });

  it('returns null for unsupported items in a mixed batch', () => {
    const results = parseBatchCheckResponse(
      {
        results: [
          { product: 'nginx', version: '1.25.3', result: NGINX_VULNERABLE },
          { product: 'fake', version: '9.9.9', result: UNSUPPORTED },
        ],
      },
      [
        { product: 'nginx', version: '1.25.3' },
        { product: 'fake', version: '9.9.9' },
      ],
    );
    expect(results).toHaveLength(2);
    expect(results[0]?.product).toBe('nginx');
    expect(results[1]).toBeNull();
  });

  it('throws when results key is missing', () => {
    expect(() =>
      parseBatchCheckResponse({}, [{ product: 'nginx', version: '1.25.3' }]),
    ).toThrow(AttestdAPIError);
  });
});

describe('parseRetryAfter', () => {
  it('parses integer seconds', () => {
    const headers = new Headers({ 'retry-after': '45' });
    expect(parseRetryAfter(headers)).toBe(45);
  });

  it('parses HTTP-date values', () => {
    const retryAt = new Date(Date.now() + 60_000).toUTCString();
    const headers = new Headers({ 'retry-after': retryAt });
    const parsed = parseRetryAfter(headers);
    expect(parsed).not.toBeNull();
    expect(parsed!).toBeGreaterThanOrEqual(55);
    expect(parsed!).toBeLessThanOrEqual(65);
  });
});
