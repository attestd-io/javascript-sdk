import { describe, it, expect } from 'vitest';
import { parseCheckResponse, parseRetryAfter } from '../src/internal.js';
import { AttestdAPIError } from '../src/errors.js';
import { NGINX_VULNERABLE } from '../src/testing.js';

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
    });
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
