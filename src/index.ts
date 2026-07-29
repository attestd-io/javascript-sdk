export { Client } from './client.js';
export type { ClientOptions } from './client.js';

export type {
  RiskState,
  RiskFactor,
  SupplyChainSignal,
  TyposquatSignal,
  CveSummary,
  RiskResult,
  BatchCheckItem,
  ProductEntry,
  SupplyChainEntry,
  ProductsResult,
  CveDetail,
  UsageResult,
  CachePolicy,
  SessionStats,
} from './models.js';

export {
  AttestdError,
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  AttestdAPIError,
} from './errors.js';

export { VERSION } from './version.js';
