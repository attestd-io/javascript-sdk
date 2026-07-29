export type RiskState = 'critical' | 'high' | 'elevated' | 'low' | 'none';

export type RiskFactor =
  | 'active_exploitation'
  | 'remote_code_execution'
  | 'no_authentication_required'
  | 'internet_exposed_service'
  | 'patch_available';

export interface TyposquatSignal {
  detected: boolean;
  resembles: string | null;
  confidence: number;
  ecosystem: string;
  kind: 'typosquat' | 'hallucination';
  likelyIntended: string[];
}

export interface CveSummary {
  cveId: string;
  cvssScore: number | null;
  activelyExploited: boolean;
  remoteExploitable: boolean;
  epssScore: number | null;
  epssPercentile: number | null;
}

export interface SupplyChainSignal {
  compromised: boolean;
  sources: string[];
  malwareType: string | null;
  description: string | null;
  advisoryUrl: string | null;
  compromisedAt: Date | null;
  removedAt: Date | null;
  /** true = attested; false = baseline drop; null = no baseline / not a signal */
  provenance: boolean | null;
}

export interface BatchCheckItem {
  product: string;
  version: string;
}

export interface RiskResult {
  product: string;
  version: string;
  riskState: RiskState;
  riskFactors: RiskFactor[];
  activelyExploited: boolean;
  remoteExploitable: boolean;
  authenticationRequired: boolean;
  patchAvailable: boolean;
  fixedVersion: string | null;
  confidence: number;
  cveIds: string[];
  maxEpss: number | null;
  cves: CveSummary[];
  lastUpdated: Date;
  supplyChain: SupplyChainSignal | null;
  typosquat: TyposquatSignal | null;
}

export interface ProductEntry {
  slug: string;
  displayName: string;
}

export interface SupplyChainEntry {
  package: string;
  ecosystem: string;
  displayName: string | null;
}

export interface ProductsResult {
  cveProducts: ProductEntry[];
  supplyChainPackages: SupplyChainEntry[];
  total: number;
}

export interface CveDetail {
  cveId: string;
  description: string | null;
  cvssScore: number | null;
  cvssVector: string | null;
  activelyExploited: boolean;
  remoteExploitable: boolean;
  authenticationRequired: boolean;
  affectedProducts: string[];
  epssScore: number | null;
  epssPercentile: number | null;
  sourcePublishedAt: Date | null;
  lastCheckedAt: Date | null;
}

export interface UsageResult {
  tier: string;
  keyCallsThisMonth: number;
  accountCallsThisMonth: number;
  includedCalls: number;
  billingPeriodStart: Date;
  billingPeriodEnd: Date;
  overageCalls: number;
  estimatedOverageUsd: number;
}

export type CachePolicy = 'development' | 'runtime' | 'ci' | 'none';

/** Observability counters for one Client lifetime. */
export interface SessionStats {
  apiCallsMade: number;
  cacheHits: number;
  batchSaves: number;
  /** Total API calls avoided via cache hits and batch coalescing. */
  readonly callsSaved: number;
}
