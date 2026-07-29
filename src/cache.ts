/**
 * Client-side result cache and session observability.
 *
 * CachePolicy and SessionStats are defined in models.ts and re-exported from
 * index.ts. ResultCache is internal.
 */

import type { CachePolicy, RiskResult, SessionStats } from './models.js';

export type { CachePolicy, SessionStats } from './models.js';

/** Bump when the in-memory entry shape changes. */
export const CACHE_VERSION = 1;

/** TTL in milliseconds. null = never expire. 0 = always miss. */
const POLICY_TTL_MS: Record<CachePolicy, number | null> = {
  development: 86_400_000,
  runtime: 300_000,
  ci: null,
  none: 0,
};

interface CacheEntry {
  result: RiskResult;
  storedAt: number;
}

export class ResultCache {
  private readonly policy: CachePolicy;
  private readonly ttlMs: number | null;
  private readonly store = new Map<string, CacheEntry>();
  private apiCallsMade = 0;
  private cacheHits = 0;
  private batchSaves = 0;

  constructor(policy: CachePolicy = 'runtime') {
    if (!(policy in POLICY_TTL_MS)) {
      throw new Error(
        `Unknown cachePolicy "${policy}". Expected one of: ${Object.keys(POLICY_TTL_MS).join(', ')}.`,
      );
    }
    this.policy = policy;
    this.ttlMs = POLICY_TTL_MS[policy];
  }

  getPolicy(): CachePolicy {
    return this.policy;
  }

  private key(product: string, version: string): string {
    return `${product}\0${version}`;
  }

  get(product: string, version: string, now = Date.now()): RiskResult | null {
    if (this.ttlMs === 0) return null;
    const entry = this.store.get(this.key(product, version));
    if (!entry) return null;
    if (this.ttlMs !== null && now - entry.storedAt >= this.ttlMs) {
      this.store.delete(this.key(product, version));
      return null;
    }
    this.cacheHits += 1;
    return entry.result;
  }

  put(product: string, version: string, result: RiskResult, now = Date.now()): void {
    if (this.ttlMs === 0) return;
    this.store.set(this.key(product, version), { result, storedAt: now });
  }

  invalidate(product: string, version: string): void {
    this.store.delete(this.key(product, version));
  }

  recordApiCall(n = 1): void {
    this.apiCallsMade += n;
  }

  recordBatchSave(n: number): void {
    if (n <= 0) return;
    this.batchSaves += n;
  }

  stats(): SessionStats {
    const apiCallsMade = this.apiCallsMade;
    const cacheHits = this.cacheHits;
    const batchSaves = this.batchSaves;
    return {
      apiCallsMade,
      cacheHits,
      batchSaves,
      get callsSaved() {
        return cacheHits + batchSaves;
      },
    };
  }
}
