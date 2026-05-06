/**
 * Testing utilities for the Attestd JS SDK.
 *
 * Import from 'attestd/testing'. Not included in the main bundle.
 *
 * @example
 * ```ts
 * import { Client } from 'attestd';
 * import { MockFetch, NGINX_VULNERABLE } from 'attestd/testing';
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
declare const UNSUPPORTED: {
    error: string;
    message: string;
};
declare const LITELLM_SAFE: {
    product: string;
    version: string;
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

export { LITELLM_COMPROMISED, LITELLM_SAFE, LOG4J_CRITICAL, MockFetch, NGINX_SAFE, NGINX_VULNERABLE, PYTORCH_LIGHTNING_COMPROMISED, SequentialMockFetch, UNSUPPORTED };
