import type { RiskResult, SupplyChainSignal, RiskState, RiskFactor, TyposquatSignal, BatchCheckItem } from './models.js';
import {
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  AttestdAPIError,
} from './errors.js';

export const DEFAULT_BASE_URL = 'https://api.attestd.io';
export const CHECK_PATH = '/v1/check';
export const BATCH_CHECK_PATH = '/v1/check/batch';
export const RETRY_STATUS_CODES = new Set([500, 502, 503, 504]);

const VALID_RISK_STATES = new Set<RiskState>([
  'critical',
  'high',
  'elevated',
  'low',
  'none',
]);

const VALID_RISK_FACTORS = new Set<RiskFactor>([
  'active_exploitation',
  'remote_code_execution',
  'no_authentication_required',
  'internet_exposed_service',
  'patch_available',
]);

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

function assertRiskState(val: unknown): RiskState {
  const state = assertString(val, 'risk_state');
  if (!VALID_RISK_STATES.has(state as RiskState)) {
    throw new AttestdAPIError(
      `Unexpected response shape: invalid risk_state ${JSON.stringify(state)}`,
      200,
    );
  }
  return state as RiskState;
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

export function parseTyposquat(raw: unknown): TyposquatSignal | null {
  if (raw === null || raw === undefined) return null;

  if (typeof raw !== 'object' || Array.isArray(raw)) {
    throw new AttestdAPIError('Unexpected response shape: typosquat is not an object', 200);
  }

  const r = raw as Record<string, unknown>;

  return {
    detected: assertBoolean(r['detected'], 'typosquat.detected'),
    resembles: r['resembles'] != null ? assertString(r['resembles'], 'typosquat.resembles') : null,
    confidence: assertNumber(r['confidence'], 'typosquat.confidence'),
    ecosystem: assertString(r['ecosystem'], 'typosquat.ecosystem'),
  };
}

function parseOptionalIso(raw: unknown, field: string): Date | null {
  if (raw === null || raw === undefined) return null;
  if (typeof raw !== 'string') {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected string, got ${typeof raw}`,
      200,
    );
  }
  const date = new Date(raw);
  if (isNaN(date.getTime())) {
    throw new AttestdAPIError(
      `Unexpected response shape: invalid ISO datetime: ${JSON.stringify(raw)}`,
      200,
    );
  }
  return date;
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
    compromisedAt: parseOptionalIso(r['compromised_at'], 'supply_chain.compromised_at'),
    removedAt: parseOptionalIso(r['removed_at'], 'supply_chain.removed_at'),
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
  const typosquat = parseTyposquat(d['typosquat'] ?? null);

  if (!('supported' in d)) {
    throw new AttestdAPIError("Unexpected response shape: missing 'supported'", 200);
  }
  if (typeof d['supported'] !== 'boolean') {
    throw new AttestdAPIError("Unexpected response shape: 'supported' expected boolean", 200);
  }

  if (!('risk_state' in d)) {
    throw new AttestdAPIError("Unexpected response shape: missing 'risk_state'", 200);
  }

  return {
    product: assertString(d['product'] ?? product, 'product'),
    version: assertString(d['version'] ?? version, 'version'),
    riskState: assertRiskState(d['risk_state']),
    riskFactors: Array.isArray(d['risk_factors'])
      ? (d['risk_factors'] as unknown[]).filter(
          (x): x is RiskFactor =>
            typeof x === 'string' && VALID_RISK_FACTORS.has(x as RiskFactor),
        )
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
    typosquat,
  };
}

export function parseRetryAfter(headers: Headers): number | null {
  const raw = headers.get('retry-after');
  if (!raw) return null;

  const trimmed = raw.trim();
  if (/^\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10);
  }

  const date = new Date(trimmed);
  if (!isNaN(date.getTime())) {
    return Math.max(0, Math.ceil((date.getTime() - Date.now()) / 1000));
  }

  return null;
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

export function parseBatchCheckResponse(
  data: unknown,
  items: BatchCheckItem[],
): (RiskResult | null)[] {
  if (!data || typeof data !== 'object' || Array.isArray(data)) {
    throw new AttestdAPIError('Unexpected response shape from Attestd batch API', 200);
  }

  const d = data as Record<string, unknown>;

  if (!Array.isArray(d['results'])) {
    throw new AttestdAPIError("Unexpected batch response shape: missing 'results' array", 200);
  }

  const rawResults = d['results'] as unknown[];
  const out: (RiskResult | null)[] = [];

  for (let i = 0; i < rawResults.length; i++) {
    const entry = rawResults[i];
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) {
      throw new AttestdAPIError(`Unexpected batch response shape at index ${i}`, 200);
    }

    const e = entry as Record<string, unknown>;
    const result = e['result'];

    if (!result || typeof result !== 'object' || Array.isArray(result)) {
      throw new AttestdAPIError(`Unexpected batch result shape at index ${i}`, 200);
    }

    const r = result as Record<string, unknown>;
    if (r['supported'] === false) {
      out.push(null);
    } else {
      const product = typeof e['product'] === 'string' ? e['product'] : (items[i]?.product ?? '');
      const version = typeof e['version'] === 'string' ? e['version'] : (items[i]?.version ?? '');
      out.push(parseCheckResponse(result, product, version));
    }
  }

  return out;
}
