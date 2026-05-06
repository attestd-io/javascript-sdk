import { describe, it, expect } from 'vitest';
import { MockFetch, SequentialMockFetch, NGINX_SAFE, NGINX_VULNERABLE } from '../src/testing.js';

describe('MockFetch', () => {
  it('returns configured status and body', async () => {
    const mock = new MockFetch(200, NGINX_SAFE);
    const response = await mock.fn('https://example.com', {});
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body).toEqual(NGINX_SAFE);
  });

  it('tracks call count', async () => {
    const mock = new MockFetch(200, NGINX_SAFE);
    expect(mock.callCount).toBe(0);
    await mock.fn('https://example.com', {});
    await mock.fn('https://example.com', {});
    expect(mock.callCount).toBe(2);
  });

  it('returns real Response instances', async () => {
    const mock = new MockFetch(401, { error: 'unauthorized' });
    const response = await mock.fn('https://example.com', {});
    expect(response).toBeInstanceOf(Response);
    expect(response.ok).toBe(false);
    expect(response.status).toBe(401);
  });

  it('forwards extra headers', async () => {
    const mock = new MockFetch(429, {}, { 'retry-after': '60' });
    const response = await mock.fn('https://example.com', {});
    expect(response.headers.get('retry-after')).toBe('60');
  });
});

describe('SequentialMockFetch', () => {
  it('returns responses in order', async () => {
    const seq = new SequentialMockFetch([
      { statusCode: 503, body: { error: 'unavailable' } },
      { statusCode: 200, body: NGINX_VULNERABLE },
    ]);
    const r1 = await seq.fn('https://example.com', {});
    expect(r1.status).toBe(503);
    const r2 = await seq.fn('https://example.com', {});
    expect(r2.status).toBe(200);
    expect(seq.callCount).toBe(2);
  });

  it('throws when responses are exhausted', async () => {
    const seq = new SequentialMockFetch([{ statusCode: 200, body: NGINX_SAFE }]);
    await seq.fn('https://example.com', {});
    await expect(seq.fn('https://example.com', {})).rejects.toThrow('exhausted');
  });
});
