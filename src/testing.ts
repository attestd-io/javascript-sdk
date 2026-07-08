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

export class MockFetch {
  private readonly statusCode: number;
  private readonly body: object;
  private readonly extraHeaders: Record<string, string>;
  public callCount = 0;

  constructor(
    statusCode: number,
    body: object,
    extraHeaders: Record<string, string> = {},
  ) {
    this.statusCode = statusCode;
    this.body = body;
    this.extraHeaders = extraHeaders;
  }

  readonly fn: typeof globalThis.fetch = async () => {
    this.callCount++;
    return new Response(JSON.stringify(this.body), {
      status: this.statusCode,
      headers: {
        'Content-Type': 'application/json',
        ...this.extraHeaders,
      },
    });
  };
}

export class SequentialMockFetch {
  private readonly responses: Array<{ statusCode: number; body: object; headers?: Record<string, string> }>;
  private index = 0;
  public callCount = 0;

  constructor(
    responses: Array<{ statusCode: number; body: object; headers?: Record<string, string> }>,
  ) {
    this.responses = responses;
  }

  readonly fn: typeof globalThis.fetch = async () => {
    if (this.index >= this.responses.length) {
      throw new Error(
        `SequentialMockFetch exhausted: ${this.responses.length} response(s) configured but call ${this.index + 1} was made`,
      );
    }
    const { statusCode, body, headers = {} } = this.responses[this.index++];
    this.callCount++;
    return new Response(JSON.stringify(body), {
      status: statusCode,
      headers: { 'Content-Type': 'application/json', ...headers },
    });
  };
}

// ---------------------------------------------------------------------------
// Fixture bodies — raw JSON-compatible objects matching the Attestd API shape.
// All timestamps are deterministic for snapshot testing.
// ---------------------------------------------------------------------------

export const NGINX_SAFE = {
  product: 'nginx',
  version: '1.26.1',
  supported: true,
  risk_state: 'none',
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 0.95,
  cve_ids: [],
  last_updated: '2026-01-01T00:00:00Z',
  supply_chain: null,
};

export const NGINX_VULNERABLE = {
  product: 'nginx',
  version: '1.25.3',
  supported: true,
  risk_state: 'high',
  risk_factors: ['remote_code_execution', 'no_authentication_required'],
  actively_exploited: false,
  remote_exploitable: true,
  authentication_required: false,
  patch_available: true,
  fixed_version: '1.26.0',
  confidence: 0.91,
  cve_ids: ['CVE-2024-7347'],
  last_updated: '2026-01-01T00:00:00Z',
  supply_chain: null,
};

export const LOG4J_CRITICAL = {
  product: 'log4j',
  version: '2.14.1',
  supported: true,
  risk_state: 'critical',
  risk_factors: [
    'active_exploitation',
    'remote_code_execution',
    'no_authentication_required',
    'internet_exposed_service',
  ],
  actively_exploited: true,
  remote_exploitable: true,
  authentication_required: false,
  patch_available: true,
  fixed_version: '2.17.1',
  confidence: 0.99,
  cve_ids: ['CVE-2021-44228', 'CVE-2021-45046'],
  last_updated: '2026-01-01T00:00:00Z',
  supply_chain: null,
};

/** Matches live API: HTTP 200 with { supported: false }. */
export const UNSUPPORTED = { supported: false };

export const LITELLM_SAFE = {
  product: 'litellm',
  version: '1.63.0',
  supported: true,
  risk_state: 'none',
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 0.87,
  cve_ids: [],
  last_updated: '2026-01-01T00:00:00Z',
  supply_chain: {
    compromised: false,
    sources: [],
    malware_type: null,
    description: null,
    advisory_url: null,
    compromised_at: null,
    removed_at: null,
  },
};

export const LITELLM_COMPROMISED = {
  product: 'litellm',
  version: '1.57.3',
  supported: true,
  risk_state: 'none',
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 0.87,
  cve_ids: [],
  last_updated: '2026-01-01T00:00:00Z',
  supply_chain: {
    compromised: true,
    sources: ['osv'],
    malware_type: 'credential_stealer',
    description: 'TeamPCP supply chain attack: credential stealer in proxy_server.py',
    advisory_url: 'https://osv.dev/vulnerability/MAL-2024-9734',
    compromised_at: '2024-11-09T00:00:00Z',
    removed_at: null,
  },
};

export const PYTORCH_LIGHTNING_COMPROMISED = {
  product: 'pytorch-lightning',
  version: '2.6.3',
  supported: true,
  risk_state: 'none',
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 0.92,
  cve_ids: [],
  last_updated: '2026-04-30T00:00:00Z',
  supply_chain: {
    compromised: true,
    sources: ['osv'],
    malware_type: 'backdoor',
    description:
      'ShaiWorm payload. Downloads Bun JS runtime on import and executes obfuscated credential stealer targeting cloud credentials, browser data, and environment secrets.',
    advisory_url: 'https://github.com/Lightning-AI/pytorch-lightning/issues/21689',
    compromised_at: '2026-04-30T00:00:00Z',
    removed_at: null,
  },
};

export const BITWARDEN_CLI_SAFE = {
  product: '@bitwarden/cli',
  version: '2026.3.0',
  supported: true,
  risk_state: 'none',
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 1.0,
  cve_ids: [],
  last_updated: '2026-05-01T00:00:00Z',
  supply_chain: {
    compromised: false,
    sources: [],
    malware_type: null,
    description: null,
    advisory_url: null,
    compromised_at: null,
    removed_at: null,
  },
};

export const BITWARDEN_CLI_COMPROMISED = {
  product: '@bitwarden/cli',
  version: '2026.4.0',
  supported: true,
  risk_state: 'none',
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 1.0,
  cve_ids: [],
  last_updated: '2026-04-22T19:30:00Z',
  supply_chain: {
    compromised: true,
    sources: ['registry'],
    malware_type: 'backdoor',
    description:
      'TeamPCP supply chain attack via compromised GitHub Actions CI/CD pipeline. Credential stealer targets SSH keys, cloud credentials, Claude Code auth tokens, and MCP configs.',
    advisory_url:
      'https://www.bleepingcomputer.com/news/security/bitwarden-cli-npm-package-compromised-to-steal-developer-credentials/',
    compromised_at: '2026-04-22T17:57:00Z',
    removed_at: '2026-04-22T19:30:00Z',
  },
};

export const PRODUCTS_RESPONSE = {
  cve_products: [
    { slug: 'nginx', display_name: 'NGINX' },
    { slug: 'postgresql', display_name: 'PostgreSQL' },
  ],
  supply_chain_packages: [{ package: 'litellm', ecosystem: 'pypi', display_name: null }],
  total: 3,
};

export const CVE_LOG4SHELL = {
  cve_id: 'CVE-2021-44228',
  description: 'Apache Log4j2 JNDI injection allows remote code execution.',
  cvss_score: 10.0,
  cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H',
  actively_exploited: true,
  remote_exploitable: true,
  authentication_required: false,
  affected_products: ['log4j'],
  epss_score: 0.97568,
  epss_percentile: 0.99976,
  source_published_at: '2021-12-10T00:00:00Z',
  last_checked_at: '2026-07-08T04:00:00Z',
};

export const USAGE_SOLO = {
  tier: 'solo',
  key_calls_this_month: 1200,
  account_calls_this_month: 1200,
  included_calls: 250000,
  billing_period_start: '2026-07-01T00:00:00Z',
  billing_period_end: '2026-08-01T00:00:00Z',
  overage_calls: 0,
  estimated_overage_usd: 0.0,
};
