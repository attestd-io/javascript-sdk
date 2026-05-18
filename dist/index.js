// src/errors.ts
var AttestdError = class extends Error {
  constructor(message) {
    super(message);
    this.name = this.constructor.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
};
var AttestdAuthError = class extends AttestdError {
  constructor(message = "Invalid or missing API key") {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
};
var AttestdRateLimitError = class extends AttestdError {
  retryAfter;
  constructor(message, retryAfter) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.retryAfter = retryAfter;
  }
};
var AttestdUnsupportedProductError = class extends AttestdError {
  product;
  version;
  constructor(product, version) {
    super(
      `Product '${product}@${version}' is outside Attestd's coverage. See https://attestd.io/docs/products for the full supported product list.`
    );
    Object.setPrototypeOf(this, new.target.prototype);
    this.product = product;
    this.version = version;
  }
};
var AttestdAPIError = class extends AttestdError {
  /** HTTP status code. 0 for network/transport failures and timeouts. */
  statusCode;
  constructor(message, statusCode) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.statusCode = statusCode;
  }
};

// src/internal.ts
var DEFAULT_BASE_URL = "https://api.attestd.io";
var CHECK_PATH = "/v1/check";
var RETRY_STATUS_CODES = /* @__PURE__ */ new Set([500, 502, 503, 504]);
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
function assertString(val, field) {
  if (typeof val !== "string") {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected string, got ${typeof val}`,
      200
    );
  }
  return val;
}
function assertBoolean(val, field) {
  if (typeof val !== "boolean") {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected boolean, got ${typeof val}`,
      200
    );
  }
  return val;
}
function assertNumber(val, field) {
  if (typeof val !== "number" || isNaN(val)) {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected number, got ${isNaN(val) ? "NaN" : typeof val}`,
      200
    );
  }
  return val;
}
function parseSupplyChain(raw) {
  if (raw === null || raw === void 0) return null;
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new AttestdAPIError("Unexpected response shape: supply_chain is not an object", 200);
  }
  const r = raw;
  return {
    compromised: assertBoolean(r["compromised"], "supply_chain.compromised"),
    sources: Array.isArray(r["sources"]) ? r["sources"].filter((x) => typeof x === "string") : [],
    malwareType: r["malware_type"] != null ? String(r["malware_type"]) : null,
    description: r["description"] != null ? String(r["description"]) : null,
    advisoryUrl: r["advisory_url"] != null ? String(r["advisory_url"]) : null,
    compromisedAt: typeof r["compromised_at"] === "string" ? new Date(r["compromised_at"]) : null,
    removedAt: typeof r["removed_at"] === "string" ? new Date(r["removed_at"]) : null
  };
}
function parseCheckResponse(data, product, version) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new AttestdAPIError("Unexpected response shape from Attestd API", 200);
  }
  const d = data;
  if (!("risk_state" in d)) {
    throw new AttestdAPIError("Unexpected response shape: missing 'risk_state'", 200);
  }
  return {
    product: assertString(d["product"] ?? product, "product"),
    version: assertString(d["version"] ?? version, "version"),
    riskState: assertString(d["risk_state"], "risk_state"),
    riskFactors: Array.isArray(d["risk_factors"]) ? d["risk_factors"].filter((x) => typeof x === "string") : [],
    activelyExploited: assertBoolean(d["actively_exploited"], "actively_exploited"),
    remoteExploitable: assertBoolean(d["remote_exploitable"], "remote_exploitable"),
    authenticationRequired: assertBoolean(
      d["authentication_required"],
      "authentication_required"
    ),
    patchAvailable: assertBoolean(d["patch_available"], "patch_available"),
    fixedVersion: d["fixed_version"] != null ? String(d["fixed_version"]) : null,
    confidence: assertNumber(d["confidence"], "confidence"),
    cveIds: Array.isArray(d["cve_ids"]) ? d["cve_ids"].filter((x) => typeof x === "string") : [],
    lastUpdated: (() => {
      if (typeof d["last_updated"] !== "string") {
        throw new AttestdAPIError(
          "Unexpected response shape: 'last_updated' expected string",
          200
        );
      }
      const date = new Date(d["last_updated"]);
      if (isNaN(date.getTime())) {
        throw new AttestdAPIError(
          `Unexpected response shape: 'last_updated' is not a valid date: ${d["last_updated"]}`,
          200
        );
      }
      return date;
    })(),
    supplyChain: parseSupplyChain(d["supply_chain"] ?? null)
  };
}
function parseRetryAfter(headers) {
  const raw = headers.get("retry-after");
  if (!raw) return null;
  const parsed = parseInt(raw, 10);
  return isNaN(parsed) ? null : parsed;
}
function buildAttestdError(status, body, product, version, retryAfterHeaders) {
  if (status === 401) {
    return new AttestdAuthError();
  }
  if (status === 429) {
    return new AttestdRateLimitError("Rate limit exceeded", parseRetryAfter(retryAfterHeaders));
  }
  if (status === 404) {
    return new AttestdUnsupportedProductError(product, version);
  }
  return new AttestdAPIError(
    `Attestd API returned status ${status}: ${body.slice(0, 200)}`,
    status
  );
}

// src/version.ts
var VERSION = "0.1.1";

// src/client.ts
var Client = class {
  apiKey;
  baseUrl;
  timeout;
  maxRetries;
  retryDelayMs;
  fetchImpl;
  constructor(options) {
    if (!options.apiKey) {
      throw new AttestdError("attestd: apiKey is required");
    }
    this.apiKey = options.apiKey;
    this.baseUrl = (options.baseUrl ?? DEFAULT_BASE_URL).replace(/\/$/, "");
    this.timeout = options.timeout ?? 1e4;
    this.maxRetries = options.maxRetries ?? 3;
    this.retryDelayMs = options.retryDelayMs ?? 1e3;
    this.fetchImpl = options.fetch ?? globalThis.fetch;
  }
  async check(product, version) {
    const url = `${this.baseUrl}${CHECK_PATH}?product=${encodeURIComponent(product)}&version=${encodeURIComponent(version)}`;
    let lastError = null;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await sleep(this.retryDelayMs * Math.pow(2, attempt - 1));
      }
      let response;
      try {
        response = await this.fetchImpl(url, {
          method: "GET",
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "User-Agent": `attestd-js/${VERSION}`,
            Accept: "application/json"
          },
          signal: AbortSignal.timeout(this.timeout)
        });
      } catch (err) {
        const isTimeout = err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
        if (isTimeout) {
          throw new AttestdAPIError(
            `Request timed out after ${this.timeout}ms`,
            0
          );
        }
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < this.maxRetries) continue;
        throw new AttestdAPIError(
          `Network error: ${lastError.message}`,
          0
        );
      }
      if (response.ok) {
        let data;
        try {
          data = await response.json();
        } catch {
          throw new AttestdAPIError("Failed to parse Attestd API response as JSON", 200);
        }
        if (data && typeof data === "object" && !Array.isArray(data) && data.supported === false) {
          throw new AttestdUnsupportedProductError(product, version);
        }
        return parseCheckResponse(data, product, version);
      }
      if (!RETRY_STATUS_CODES.has(response.status) || attempt === this.maxRetries) {
        const body = await response.text().catch(() => "");
        throw buildAttestdError(response.status, body, product, version, response.headers);
      }
      lastError = new AttestdAPIError(
        `Attestd API returned status ${response.status}`,
        response.status
      );
    }
    throw lastError ?? new AttestdAPIError("Unknown error", 0);
  }
};

export { AttestdAPIError, AttestdAuthError, AttestdError, AttestdRateLimitError, AttestdUnsupportedProductError, Client, VERSION };
//# sourceMappingURL=index.js.map
//# sourceMappingURL=index.js.map