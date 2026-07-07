export { Client } from './client.js';
export type { ClientOptions } from './client.js';

export type {
  RiskState,
  RiskFactor,
  SupplyChainSignal,
  TyposquatSignal,
  RiskResult,
  BatchCheckItem,
} from './models.js';

export {
  AttestdError,
  AttestdAuthError,
  AttestdRateLimitError,
  AttestdUnsupportedProductError,
  AttestdAPIError,
} from './errors.js';

export { VERSION } from './version.js';
