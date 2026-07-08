/**
 * Testing utilities for the Attestd JS SDK.
 *
 * Import from '@attestd/sdk/testing'. Not included in the main bundle.
 *
 * @example
 * ```ts
 * import { Client } from '@attestd/sdk';
 * import { MockFetch, NGINX_VULNERABLE } from '@attestd/sdk/testing';
 *
 * const mock = new MockFetch(200, NGINX_VULNERABLE);
 * const client = new Client({ apiKey: 'test', fetch: mock.fn });
 * const result = await client.check('nginx', '1.25.3');
 * ```
 */
declare class MockFetch {
    private readonly statusCode;
    private readonly body;
    private readonly extraHeaders;
    callCount: number;
    constructor(statusCode: number, body: object, extraHeaders?: Record<string, string>);
    readonly fn: typeof globalThis.fetch;
}
declare class SequentialMockFetch {
    private readonly responses;
    private index;
    callCount: number;
    constructor(responses: Array<{
        statusCode: number;
        body: object;
        headers?: Record<string, string>;
    }>);
    readonly fn: typeof globalThis.fetch;
}
declare const NGINX_SAFE: {
    product: string;
    version: string;
    supported: boolean;
    risk_state: string;
    risk_factors: never[];
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    patch_available: boolean;
    fixed_version: null;
    confidence: number;
    cve_ids: never[];
    last_updated: string;
    supply_chain: null;
};
declare const NGINX_VULNERABLE: {
    product: string;
    version: string;
    supported: boolean;
    risk_state: string;
    risk_factors: string[];
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    patch_available: boolean;
    fixed_version: string;
    confidence: number;
    cve_ids: string[];
    last_updated: string;
    supply_chain: null;
};
declare const LOG4J_CRITICAL: {
    product: string;
    version: string;
    supported: boolean;
    risk_state: string;
    risk_factors: string[];
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    patch_available: boolean;
    fixed_version: string;
    confidence: number;
    cve_ids: string[];
    last_updated: string;
    supply_chain: null;
};
/** Matches live API: HTTP 200 with { supported: false }. */
declare const UNSUPPORTED: {
    supported: boolean;
};
declare const LITELLM_SAFE: {
    product: string;
    version: string;
    supported: boolean;
    risk_state: string;
    risk_factors: never[];
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    patch_available: boolean;
    fixed_version: null;
    confidence: number;
    cve_ids: never[];
    last_updated: string;
    supply_chain: {
        compromised: boolean;
        sources: never[];
        malware_type: null;
        description: null;
        advisory_url: null;
        compromised_at: null;
        removed_at: null;
    };
};
declare const LITELLM_COMPROMISED: {
    product: string;
    version: string;
    supported: boolean;
    risk_state: string;
    risk_factors: never[];
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    patch_available: boolean;
    fixed_version: null;
    confidence: number;
    cve_ids: never[];
    last_updated: string;
    supply_chain: {
        compromised: boolean;
        sources: string[];
        malware_type: string;
        description: string;
        advisory_url: string;
        compromised_at: string;
        removed_at: null;
    };
};
declare const PYTORCH_LIGHTNING_COMPROMISED: {
    product: string;
    version: string;
    supported: boolean;
    risk_state: string;
    risk_factors: never[];
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    patch_available: boolean;
    fixed_version: null;
    confidence: number;
    cve_ids: never[];
    last_updated: string;
    supply_chain: {
        compromised: boolean;
        sources: string[];
        malware_type: string;
        description: string;
        advisory_url: string;
        compromised_at: string;
        removed_at: null;
    };
};
declare const BITWARDEN_CLI_SAFE: {
    product: string;
    version: string;
    supported: boolean;
    risk_state: string;
    risk_factors: never[];
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    patch_available: boolean;
    fixed_version: null;
    confidence: number;
    cve_ids: never[];
    last_updated: string;
    supply_chain: {
        compromised: boolean;
        sources: never[];
        malware_type: null;
        description: null;
        advisory_url: null;
        compromised_at: null;
        removed_at: null;
    };
};
declare const BITWARDEN_CLI_COMPROMISED: {
    product: string;
    version: string;
    supported: boolean;
    risk_state: string;
    risk_factors: never[];
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    patch_available: boolean;
    fixed_version: null;
    confidence: number;
    cve_ids: never[];
    last_updated: string;
    supply_chain: {
        compromised: boolean;
        sources: string[];
        malware_type: string;
        description: string;
        advisory_url: string;
        compromised_at: string;
        removed_at: string;
    };
};
declare const PRODUCTS_RESPONSE: {
    cve_products: {
        slug: string;
        display_name: string;
    }[];
    supply_chain_packages: {
        package: string;
        ecosystem: string;
        display_name: null;
    }[];
    total: number;
};
declare const CVE_LOG4SHELL: {
    cve_id: string;
    description: string;
    cvss_score: number;
    cvss_vector: string;
    actively_exploited: boolean;
    remote_exploitable: boolean;
    authentication_required: boolean;
    affected_products: string[];
    epss_score: number;
    epss_percentile: number;
    source_published_at: string;
    last_checked_at: string;
};
declare const USAGE_SOLO: {
    tier: string;
    key_calls_this_month: number;
    account_calls_this_month: number;
    included_calls: number;
    billing_period_start: string;
    billing_period_end: string;
    overage_calls: number;
    estimated_overage_usd: number;
};

export { BITWARDEN_CLI_COMPROMISED, BITWARDEN_CLI_SAFE, CVE_LOG4SHELL, LITELLM_COMPROMISED, LITELLM_SAFE, LOG4J_CRITICAL, MockFetch, NGINX_SAFE, NGINX_VULNERABLE, PRODUCTS_RESPONSE, PYTORCH_LIGHTNING_COMPROMISED, SequentialMockFetch, UNSUPPORTED, USAGE_SOLO };
