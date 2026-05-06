// src/testing.ts
var MockFetch = class {
  statusCode;
  body;
  extraHeaders;
  callCount = 0;
  constructor(statusCode, body, extraHeaders = {}) {
    this.statusCode = statusCode;
    this.body = body;
    this.extraHeaders = extraHeaders;
  }
  fn = async () => {
    this.callCount++;
    return new Response(JSON.stringify(this.body), {
      status: this.statusCode,
      headers: {
        "Content-Type": "application/json",
        ...this.extraHeaders
      }
    });
  };
};
var SequentialMockFetch = class {
  responses;
  index = 0;
  callCount = 0;
  constructor(responses) {
    this.responses = responses;
  }
  fn = async () => {
    if (this.index >= this.responses.length) {
      throw new Error(
        `SequentialMockFetch exhausted: ${this.responses.length} response(s) configured but call ${this.index + 1} was made`
      );
    }
    const { statusCode, body, headers = {} } = this.responses[this.index++];
    this.callCount++;
    return new Response(JSON.stringify(body), {
      status: statusCode,
      headers: { "Content-Type": "application/json", ...headers }
    });
  };
};
var NGINX_SAFE = {
  product: "nginx",
  version: "1.26.1",
  risk_state: "none",
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 0.95,
  cve_ids: [],
  last_updated: "2026-01-01T00:00:00Z",
  supply_chain: null
};
var NGINX_VULNERABLE = {
  product: "nginx",
  version: "1.25.3",
  risk_state: "high",
  risk_factors: ["remote_code_execution", "no_authentication_required"],
  actively_exploited: false,
  remote_exploitable: true,
  authentication_required: false,
  patch_available: true,
  fixed_version: "1.26.0",
  confidence: 0.91,
  cve_ids: ["CVE-2024-7347"],
  last_updated: "2026-01-01T00:00:00Z",
  supply_chain: null
};
var LOG4J_CRITICAL = {
  product: "log4j",
  version: "2.14.1",
  risk_state: "critical",
  risk_factors: [
    "active_exploitation",
    "remote_code_execution",
    "no_authentication_required",
    "internet_exposed_service"
  ],
  actively_exploited: true,
  remote_exploitable: true,
  authentication_required: false,
  patch_available: true,
  fixed_version: "2.17.1",
  confidence: 0.99,
  cve_ids: ["CVE-2021-44228", "CVE-2021-45046"],
  last_updated: "2026-01-01T00:00:00Z",
  supply_chain: null
};
var UNSUPPORTED = {
  error: "unsupported_product",
  message: "Product 'unknown-thing' is outside Attestd's coverage."
};
var LITELLM_SAFE = {
  product: "litellm",
  version: "1.63.0",
  risk_state: "none",
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 0.87,
  cve_ids: [],
  last_updated: "2026-01-01T00:00:00Z",
  supply_chain: {
    compromised: false,
    sources: [],
    malware_type: null,
    description: null,
    advisory_url: null,
    compromised_at: null,
    removed_at: null
  }
};
var LITELLM_COMPROMISED = {
  product: "litellm",
  version: "1.57.3",
  risk_state: "none",
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 0.87,
  cve_ids: [],
  last_updated: "2026-01-01T00:00:00Z",
  supply_chain: {
    compromised: true,
    sources: ["osv"],
    malware_type: "credential_stealer",
    description: "TeamPCP supply chain attack: credential stealer in proxy_server.py",
    advisory_url: "https://osv.dev/vulnerability/MAL-2024-9734",
    compromised_at: "2024-11-09T00:00:00Z",
    removed_at: null
  }
};
var PYTORCH_LIGHTNING_COMPROMISED = {
  product: "pytorch-lightning",
  version: "2.6.3",
  risk_state: "none",
  risk_factors: [],
  actively_exploited: false,
  remote_exploitable: false,
  authentication_required: false,
  patch_available: false,
  fixed_version: null,
  confidence: 0.92,
  cve_ids: [],
  last_updated: "2026-04-30T00:00:00Z",
  supply_chain: {
    compromised: true,
    sources: ["osv"],
    malware_type: "backdoor",
    description: "ShaiWorm payload. Downloads Bun JS runtime on import and executes obfuscated credential stealer targeting cloud credentials, browser data, and environment secrets.",
    advisory_url: "https://github.com/Lightning-AI/pytorch-lightning/issues/21689",
    compromised_at: "2026-04-30T00:00:00Z",
    removed_at: null
  }
};

export { LITELLM_COMPROMISED, LITELLM_SAFE, LOG4J_CRITICAL, MockFetch, NGINX_SAFE, NGINX_VULNERABLE, PYTORCH_LIGHTNING_COMPROMISED, SequentialMockFetch, UNSUPPORTED };
//# sourceMappingURL=testing.js.map
//# sourceMappingURL=testing.js.map