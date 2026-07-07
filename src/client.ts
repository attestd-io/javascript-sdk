import type { RiskResult, BatchCheckItem } from './models.js';
import { AttestdError, AttestdAPIError, AttestdUnsupportedProductError } from './errors.js';
import {
  DEFAULT_BASE_URL,
  CHECK_PATH,
  BATCH_CHECK_PATH,
  RETRY_STATUS_CODES,
  sleep,
  parseCheckResponse,
  parseBatchCheckResponse,
  parseTyposquat,
  buildAttestdError,
} from './internal.js';
import { VERSION } from './version.js';

export interface ClientOptions {
  /** Attestd API key (atst_...). Falls back to ATTESTD_API_KEY env var. */
  apiKey?: string;
  /** Override the base URL. Falls back to ATTESTD_BASE_URL env var, then https://api.attestd.io. */
  baseUrl?: string;
  /** Per-request timeout in milliseconds. Defaults to 10 000. */
  timeout?: number;
  /** Maximum retry attempts on 5xx responses. Defaults to 3. */
  maxRetries?: number;
  /**
   * Custom fetch implementation. Defaults to globalThis.fetch.
   * Inject MockFetch / SequentialMockFetch from attestd/testing for unit tests.
   */
  fetch?: typeof globalThis.fetch;
  /**
   * Base delay in ms for exponential backoff between retries. Defaults to 1 000.
   * Set to a small value (e.g. 10) in unit tests to keep retry tests fast.
   */
  retryDelayMs?: number;
}

export class Client {
  private readonly apiKey: string;
  private readonly baseUrl: string;
  private readonly timeout: number;
  private readonly maxRetries: number;
  private readonly retryDelayMs: number;
  private readonly fetchImpl: typeof globalThis.fetch;

  constructor(options: ClientOptions = {}) {
    const env = typeof process !== 'undefined' ? process.env : {};
    const apiKey = (options.apiKey ?? env.ATTESTD_API_KEY ?? '').trim();
    if (!apiKey) {
      throw new AttestdError(
        'attestd: apiKey is required. Pass it to Client() or set the ATTESTD_API_KEY environment variable.',
      );
    }
    this.apiKey = apiKey;
    this.baseUrl = (options.baseUrl ?? env.ATTESTD_BASE_URL ?? DEFAULT_BASE_URL).replace(/\/$/, '');
    this.timeout = options.timeout ?? 10_000;
    this.maxRetries = options.maxRetries ?? 3;
    this.retryDelayMs = options.retryDelayMs ?? 1_000;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }

  async check(product: string, version: string): Promise<RiskResult> {
    const url = `${this.baseUrl}${CHECK_PATH}?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}`;

    let lastError: Error | null = null;

    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await sleep(this.retryDelayMs * Math.pow(2, attempt - 1));
      }

      let response: Response;

      try {
        response = await this.fetchImpl(url, {
          method: 'GET',
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            'User-Agent': `attestd-js/${VERSION}`,
            Accept: 'application/json',
          },
          signal: AbortSignal.timeout(this.timeout),
        });
      } catch (err) {
        const isTimeout =
          err instanceof Error &&
          (err.name === 'TimeoutError' || err.name === 'AbortError');

        if (isTimeout) {
          throw new AttestdAPIError(
            `Request timed out after ${this.timeout}ms`,
            0,
          );
        }

        lastError = err instanceof Error ? err : new Error(String(err));

        if (attempt < this.maxRetries) continue;

        throw new AttestdAPIError(
          `Network error: ${lastError.message}`,
          0,
        );
      }

      if (response.ok) {
        let data: unknown;
        try {
          data = await response.json();
        } catch {
          throw new AttestdAPIError('Failed to parse Attestd API response as JSON', 200);
        }
      if (
        data &&
        typeof data === 'object' &&
        !Array.isArray(data) &&
        'supported' in data &&
        (data as Record<string, unknown>).supported === false
      ) {
        const typosquat = parseTyposquat((data as Record<string, unknown>).typosquat ?? null);
        throw new AttestdUnsupportedProductError(product, version, typosquat);
      }
      return parseCheckResponse(data, product, version);
    }

    if (!RETRY_STATUS_CODES.has(response.status) || attempt === this.maxRetries) {
      const body = await response.text().catch(() => '');
      throw buildAttestdError(response.status, body, product, version, response.headers);
    }

    await response.text().catch(() => '');

    lastError = new AttestdAPIError(
      `Attestd API returned status ${response.status}`,
      response.status,
    );
  }

  throw lastError ?? new AttestdAPIError('Unknown error', 0);
}

async checkBatch(items: BatchCheckItem[]): Promise<(RiskResult | null)[]> {
  if (items.length === 0) return [];
  if (items.length > 100) {
    throw new AttestdError(
      `attestd: checkBatch accepts at most 100 items; got ${items.length}`,
    );
  }

  const url = `${this.baseUrl}${BATCH_CHECK_PATH}`;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
    if (attempt > 0) {
      await sleep(this.retryDelayMs * Math.pow(2, attempt - 1));
    }

    let response: Response;

    try {
      response = await this.fetchImpl(url, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${this.apiKey}`,
          'User-Agent': `attestd-js/${VERSION}`,
          Accept: 'application/json',
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ items }),
        signal: AbortSignal.timeout(this.timeout),
      });
    } catch (err) {
      const isTimeout =
        err instanceof Error &&
        (err.name === 'TimeoutError' || err.name === 'AbortError');

      if (isTimeout) {
        throw new AttestdAPIError(`Request timed out after ${this.timeout}ms`, 0);
      }

      lastError = err instanceof Error ? err : new Error(String(err));

      if (attempt < this.maxRetries) continue;

      throw new AttestdAPIError(`Network error: ${lastError.message}`, 0);
    }

    if (response.ok) {
      let data: unknown;
      try {
        data = await response.json();
      } catch {
        throw new AttestdAPIError('Failed to parse Attestd batch API response as JSON', 200);
      }
      return parseBatchCheckResponse(data, items);
    }

    if (!RETRY_STATUS_CODES.has(response.status) || attempt === this.maxRetries) {
      const body = await response.text().catch(() => '');
      throw buildAttestdError(response.status, body, '', '', response.headers);
    }

    await response.text().catch(() => '');

    lastError = new AttestdAPIError(
      `Attestd API returned status ${response.status}`,
      response.status,
    );
  }

  throw lastError ?? new AttestdAPIError('Unknown error', 0);
}
}
