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
