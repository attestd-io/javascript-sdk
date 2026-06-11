import { describe, it, expect } from 'vitest';
import { parseCheckResponse } from '../src/internal.js';
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
});
