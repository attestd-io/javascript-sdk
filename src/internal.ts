import type { RiskResult, SupplyChainSignal, RiskState, RiskFactor } from './models.js';
import {
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  AttestdAPIError,
} from './errors.js';

export const DEFAULT_BASE_URL = 'https://api.attestd.io';
export const CHECK_PATH = '/v1/check';
export const RETRY_STATUS_CODES = new Set([500, 502, 503, 504]);

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function assertString(val: unknown, field: string): string {
  if (typeof val !== 'string') {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected string, got ${typeof val}`,
      200,
    );
  }
  return val;
}

function assertBoolean(val: unknown, field: string): boolean {
  if (typeof val !== 'boolean') {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected boolean, got ${typeof val}`,
      200,
    );
  }
  return val;
}

function assertNumber(val: unknown, field: string): number {
  if (typeof val !== 'number' || isNaN(val)) {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected number, got ${isNaN(val as number) ? 'NaN' : typeof val}`,
      200,
    );
  }
  return val;
}

export function parseSupplyChain(raw: unknown): SupplyChainSignal | null {
  if (raw === null || raw === undefined) return null;

  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new AttestdAPIError('Unexpected response shape: supply_chain is not an object', 200);
  }

  const r = raw as Record<string, unknown>;

  return {
    compromised: assertBoolean(r['compromised'], 'supply_chain.compromised'),
    sources: Array.isArray(r['sources'])
      ? (r['sources'] as unknown[]).filter((x): x is string => typeof x === 'string')
      : [],
    malwareType: r['malware_type'] != null ? String(r['malware_type']) : null,
    description: r['description'] != null ? String(r['description']) : null,
    advisoryUrl: r['advisory_url'] != null ? String(r['advisory_url']) : null,
    compromisedAt:
      typeof r['compromised_at'] === 'string' ? new Date(r['compromised_at']) : null,
    removedAt: typeof r['removed_at'] === 'string' ? new Date(r['removed_at']) : null,
  };
}

export function parseCheckResponse(
  data: unknown,
  product: string,
  version: string,
): RiskResult {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new AttestdAPIError('Unexpected response shape from Attestd API', 200);
  }

  const d = data as Record<string, unknown>;

  if (!('risk_state' in d)) {
    throw new AttestdAPIError("Unexpected response shape: missing 'risk_state'", 200);
  }

  return {
    product: assertString(d['product'] ?? product, 'product'),
    version: assertString(d['version'] ?? version, 'version'),
    riskState: assertString(d['risk_state'], 'risk_state') as RiskState,
    riskFactors: Array.isArray(d['risk_factors'])
      ? (d['risk_factors'] as unknown[]).filter((x): x is RiskFactor => typeof x === 'string')
      : [],
    activelyExploited: assertBoolean(d['actively_exploited'], 'actively_exploited'),
    remoteExploitable: assertBoolean(d['remote_exploitable'], 'remote_exploitable'),
    authenticationRequired: assertBoolean(
      d['authentication_required'],
      'authentication_required',
    ),
    patchAvailable: assertBoolean(d['patch_available'], 'patch_available'),
    fixedVersion: d['fixed_version'] != null ? String(d['fixed_version']) : null,
    confidence: assertNumber(d['confidence'], 'confidence'),
    cveIds: Array.isArray(d['cve_ids'])
      ? (d['cve_ids'] as unknown[]).filter((x): x is string => typeof x === 'string')
      : [],
    lastUpdated: (() => {
      if (typeof d['last_updated'] !== 'string') {
        throw new AttestdAPIError(
          "Unexpected response shape: 'last_updated' expected string",
          200,
        );
      }
      const date = new Date(d['last_updated']);
      if (isNaN(date.getTime())) {
        throw new AttestdAPIError(
          `Unexpected response shape: 'last_updated' is not a valid date: ${d['last_updated']}`,
          200,
        );
      }
      return date;
    })(),
    supplyChain: parseSupplyChain(d['supply_chain'] ?? null),
  };
}

export function parseRetryAfter(headers: Headers): number | null {
  const raw = headers.get('retry-after');
  if (!raw) return null;
  const parsed = parseInt(raw, 10);
  return isNaN(parsed) ? null : parsed;
}

export function buildAttestdError(
  status: number,
  body: string,
  product: string,
  version: string,
  retryAfterHeaders: Headers,
): AttestdAuthError | AttestdRateLimitError | AttestdUnsupportedProductError | AttestdAPIError {
  if (status === 401) {
    return new AttestdAuthError();
  }
  if (status === 429) {
    return new AttestdRateLimitError('Rate limit exceeded', parseRetryAfter(retryAfterHeaders));
  }
  if (status === 404) {
    return new AttestdUnsupportedProductError(product, version);
  }
  return new AttestdAPIError(
    `Attestd API returned status ${status}: ${body.slice(0, 200)}`,
    status,
  );
}
