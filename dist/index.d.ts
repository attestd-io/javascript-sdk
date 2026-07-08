type RiskState = 'critical' | 'high' | 'elevated' | 'low' | 'none';
type RiskFactor = 'active_exploitation' | 'remote_code_execution' | 'no_authentication_required' | 'internet_exposed_service' | 'patch_available';
interface TyposquatSignal {
    detected: boolean;
    resembles: string | null;
    confidence: number;
    ecosystem: string;
}
interface CveSummary {
    cveId: string;
    cvssScore: number | null;
    activelyExploited: boolean;
    remoteExploitable: boolean;
    epssScore: number | null;
    epssPercentile: number | null;
}
interface SupplyChainSignal {
    compromised: boolean;
    sources: string[];
    malwareType: string | null;
    description: string | null;
    advisoryUrl: string | null;
    compromisedAt: Date | null;
    removedAt: Date | null;
}
interface BatchCheckItem {
    product: string;
    version: string;
}
interface RiskResult {
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
interface ProductEntry {
    slug: string;
    displayName: string;
}
interface SupplyChainEntry {
    package: string;
    ecosystem: string;
    displayName: string | null;
}
interface ProductsResult {
    cveProducts: ProductEntry[];
    supplyChainPackages: SupplyChainEntry[];
    total: number;
}
interface CveDetail {
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
interface UsageResult {
    tier: string;
    keyCallsThisMonth: number;
    accountCallsThisMonth: number;
    includedCalls: number;
    billingPeriodStart: Date;
    billingPeriodEnd: Date;
    overageCalls: number;
    estimatedOverageUsd: number;
}

interface ClientOptions {
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
declare class Client {
    private readonly apiKey;
    private readonly baseUrl;
    private readonly timeout;
    private readonly maxRetries;
    private readonly retryDelayMs;
    private readonly fetchImpl;
    constructor(options?: ClientOptions);
    check(product: string, version: string): Promise<RiskResult>;
    checkBatch(items: BatchCheckItem[]): Promise<(RiskResult | null)[]>;
    products(): Promise<ProductsResult>;
    cve(cveId: string): Promise<CveDetail>;
    usage(): Promise<UsageResult>;
    private getWithRetry;
}

declare class AttestdError extends Error {
    constructor(message: string);
}
/** Thrown on 401 — invalid or missing API key. */
declare class AttestdAuthError extends AttestdError {
    constructor(message?: string);
}
/** Thrown on 429 — rate limit exceeded. */
declare class AttestdRateLimitError extends AttestdError {
    readonly retryAfter: number | null;
    constructor(message: string, retryAfter: number | null);
}
/** Thrown on 404 — the product/version combination is outside Attestd's coverage. */
declare class AttestdUnsupportedProductError extends AttestdError {
    readonly product: string;
    readonly version: string;
    readonly typosquat: TyposquatSignal | null;
    constructor(product: string, version: string, typosquat?: TyposquatSignal | null);
}
/** Thrown on unexpected HTTP status codes, malformed responses, or transport failures. */
declare class AttestdAPIError extends AttestdError {
    /** HTTP status code. 0 for network/transport failures and timeouts. */
    readonly statusCode: number;
    constructor(message: string, statusCode: number);
}

declare const VERSION: string;

export { AttestdAPIError, AttestdAuthError, AttestdError, AttestdRateLimitError, AttestdUnsupportedProductError, type BatchCheckItem, Client, type ClientOptions, type CveDetail, type CveSummary, type ProductEntry, type ProductsResult, type RiskFactor, type RiskResult, type RiskState, type SupplyChainEntry, type SupplyChainSignal, type TyposquatSignal, type UsageResult, VERSION };
