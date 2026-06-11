import { describe, it, expect } from 'vitest';
import {
  AttestdError,
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  AttestdAPIError,
} from '../src/errors.js';

describe('error class hierarchy', () => {
  it('AttestdAuthError is instanceof AttestdError and AttestdAuthError', () => {
    const err = new AttestdAuthError();
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AttestdError);
    expect(err).toBeInstanceOf(AttestdAuthError);
  });

  it('AttestdRateLimitError is instanceof AttestdError (CJS instanceof regression case)', () => {
    const err = new AttestdRateLimitError('Rate limit exceeded', 30);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AttestdError);
    expect(err).toBeInstanceOf(AttestdRateLimitError);
  });

  it('AttestdUnsupportedProductError is instanceof AttestdError', () => {
    const err = new AttestdUnsupportedProductError('unknown-lib', '1.0.0');
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AttestdError);
    expect(err).toBeInstanceOf(AttestdUnsupportedProductError);
  });

  it('AttestdAPIError is instanceof AttestdError', () => {
    const err = new AttestdAPIError('Server error', 500);
    expect(err).toBeInstanceOf(Error);
    expect(err).toBeInstanceOf(AttestdError);
    expect(err).toBeInstanceOf(AttestdAPIError);
  });
});

describe('error properties', () => {
  it('AttestdRateLimitError exposes retryAfter', () => {
    const err = new AttestdRateLimitError('Rate limit exceeded', 60);
    expect(err.retryAfter).toBe(60);
    expect(err.message).toBe('Rate limit exceeded');
    expect(err.name).toBe('AttestdRateLimitError');
  });

  it('AttestdRateLimitError retryAfter can be null', () => {
    const err = new AttestdRateLimitError('Rate limit exceeded', null);
    expect(err.retryAfter).toBeNull();
  });

  it('AttestdUnsupportedProductError exposes product and version', () => {
    const err = new AttestdUnsupportedProductError('my-lib', '2.0.0');
    expect(err.product).toBe('my-lib');
    expect(err.version).toBe('2.0.0');
    expect(err.message).toContain('my-lib@2.0.0');
    expect(err.name).toBe('AttestdUnsupportedProductError');
  });

  it('AttestdAPIError exposes statusCode', () => {
    const err = new AttestdAPIError('Unexpected response', 502);
    expect(err.statusCode).toBe(502);
    expect(err.name).toBe('AttestdAPIError');
  });

  it('AttestdUnsupportedProductError message clarifies product is not safe', () => {
    const err = new AttestdUnsupportedProductError('my-lib', '2.0.0');
    expect(err.message).toContain('does not mean the product is safe');
  });
});
