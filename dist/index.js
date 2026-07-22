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
  typosquat;
  constructor(product, version, typosquat = null) {
    super(
      `Product '${product}@${version}' is outside Attestd's coverage. This does not mean the product is safe. Attestd has no data for it. See https://attestd.io/docs/products for the full supported product list.`
    );
    Object.setPrototypeOf(this, new.target.prototype);
    this.product = product;
    this.version = version;
    this.typosquat = typosquat;
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
var BATCH_CHECK_PATH = "/v1/check/batch";
var PRODUCTS_PATH = "/v1/products";
var CVE_PATH_PREFIX = "/v1/cve/";
var USAGE_PATH = "/v1/usage";
var RETRY_STATUS_CODES = /* @__PURE__ */ new Set([500, 502, 503, 504]);
var VALID_RISK_STATES = /* @__PURE__ */ new Set([
  "critical",
  "high",
  "elevated",
  "low",
  "none"
]);
var VALID_RISK_FACTORS = /* @__PURE__ */ new Set([
  "active_exploitation",
  "remote_code_execution",
  "no_authentication_required",
  "internet_exposed_service",
  "patch_available"
]);
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
function parseOptionalBoolean(val, field) {
  if (val === null || val === void 0) return null;
  if (typeof val !== "boolean") {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected boolean | null, got ${typeof val}`,
      200
    );
  }
  return val;
}
function assertRiskState(val) {
  const state = assertString(val, "risk_state");
  if (!VALID_RISK_STATES.has(state)) {
    throw new AttestdAPIError(
      `Unexpected response shape: invalid risk_state ${JSON.stringify(state)}`,
      200
    );
  }
  return state;
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
function parseTyposquat(raw) {
  if (raw === null || raw === void 0) return null;
  if (typeof raw !== "object" || Array.isArray(raw)) {
    throw new AttestdAPIError("Unexpected response shape: typosquat is not an object", 200);
  }
  const r = raw;
  const kindRaw = r["kind"] ?? "typosquat";
  if (kindRaw !== "typosquat" && kindRaw !== "hallucination") {
    throw new AttestdAPIError(
      "Unexpected response shape: typosquat.kind expected 'typosquat' or 'hallucination'",
      200
    );
  }
  const likelyRaw = r["likely_intended"];
  let likelyIntended = [];
  if (likelyRaw != null) {
    if (!Array.isArray(likelyRaw)) {
      throw new AttestdAPIError(
        "Unexpected response shape: typosquat.likely_intended expected array",
        200
      );
    }
    likelyIntended = likelyRaw.map(
      (item, i) => assertString(item, `typosquat.likely_intended[${i}]`)
    );
  }
  return {
    detected: assertBoolean(r["detected"], "typosquat.detected"),
    resembles: r["resembles"] != null ? assertString(r["resembles"], "typosquat.resembles") : null,
    confidence: assertNumber(r["confidence"], "typosquat.confidence"),
    ecosystem: assertString(r["ecosystem"], "typosquat.ecosystem"),
    kind: kindRaw,
    likelyIntended
  };
}
function parseOptionalIso(raw, field) {
  if (raw === null || raw === void 0) return null;
  if (typeof raw !== "string") {
    throw new AttestdAPIError(
      `Unexpected response shape: '${field}' expected string, got ${typeof raw}`,
      200
    );
  }
  const date = new Date(raw);
  if (isNaN(date.getTime())) {
    throw new AttestdAPIError(
      `Unexpected response shape: invalid ISO datetime: ${JSON.stringify(raw)}`,
      200
    );
  }
  return date;
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
    compromisedAt: parseOptionalIso(r["compromised_at"], "supply_chain.compromised_at"),
    removedAt: parseOptionalIso(r["removed_at"], "supply_chain.removed_at"),
    provenance: parseOptionalBoolean(r["provenance"], "supply_chain.provenance")
  };
}
function parseCveSummaries(raw) {
  if (!Array.isArray(raw)) {
    return [];
  }
  return raw.flatMap((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) {
      return [];
    }
    const c = item;
    return [
      {
        cveId: typeof c["cve_id"] === "string" ? c["cve_id"] : "",
        cvssScore: typeof c["cvss_score"] === "number" ? c["cvss_score"] : null,
        activelyExploited: typeof c["actively_exploited"] === "boolean" ? c["actively_exploited"] : false,
        remoteExploitable: typeof c["remote_exploitable"] === "boolean" ? c["remote_exploitable"] : false,
        epssScore: typeof c["epss_score"] === "number" ? c["epss_score"] : null,
        epssPercentile: typeof c["epss_percentile"] === "number" ? c["epss_percentile"] : null
      }
    ];
  });
}
function parseCheckResponse(data, product, version) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new AttestdAPIError("Unexpected response shape from Attestd API", 200);
  }
  const d = data;
  const typosquat = parseTyposquat(d["typosquat"] ?? null);
  if (!("supported" in d)) {
    throw new AttestdAPIError("Unexpected response shape: missing 'supported'", 200);
  }
  if (typeof d["supported"] !== "boolean") {
    throw new AttestdAPIError("Unexpected response shape: 'supported' expected boolean", 200);
  }
  if (!("risk_state" in d)) {
    throw new AttestdAPIError("Unexpected response shape: missing 'risk_state'", 200);
  }
  return {
    product: assertString(d["product"] ?? product, "product"),
    version: assertString(d["version"] ?? version, "version"),
    riskState: assertRiskState(d["risk_state"]),
    riskFactors: Array.isArray(d["risk_factors"]) ? d["risk_factors"].filter(
      (x) => typeof x === "string" && VALID_RISK_FACTORS.has(x)
    ) : [],
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
    maxEpss: typeof d["max_epss"] === "number" ? d["max_epss"] : null,
    cves: parseCveSummaries(d["cves"] ?? null),
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
    supplyChain: parseSupplyChain(d["supply_chain"] ?? null),
    typosquat
  };
}
function parseRetryAfter(headers) {
  const raw = headers.get("retry-after");
  if (!raw) return null;
  const trimmed = raw.trim();
  if (/^\d+$/.test(trimmed)) {
    return parseInt(trimmed, 10);
  }
  const date = new Date(trimmed);
  if (!isNaN(date.getTime())) {
    return Math.max(0, Math.ceil((date.getTime() - Date.now()) / 1e3));
  }
  return null;
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
function parseBatchCheckResponse(data, items) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new AttestdAPIError("Unexpected response shape from Attestd batch API", 200);
  }
  const d = data;
  if (!Array.isArray(d["results"])) {
    throw new AttestdAPIError("Unexpected batch response shape: missing 'results' array", 200);
  }
  const rawResults = d["results"];
  const out = [];
  for (let i = 0; i < rawResults.length; i++) {
    const entry = rawResults[i];
    if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw new AttestdAPIError(`Unexpected batch response shape at index ${i}`, 200);
    }
    const e = entry;
    const result = e["result"];
    if (!result || typeof result !== "object" || Array.isArray(result)) {
      throw new AttestdAPIError(`Unexpected batch result shape at index ${i}`, 200);
    }
    const r = result;
    if (r["supported"] === false) {
      out.push(null);
    } else {
      const product = typeof e["product"] === "string" ? e["product"] : items[i]?.product ?? "";
      const version = typeof e["version"] === "string" ? e["version"] : items[i]?.version ?? "";
      out.push(parseCheckResponse(result, product, version));
    }
  }
  return out;
}
function parseProductsResponse(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new AttestdAPIError("Unexpected products response shape", 200);
  }
  const d = data;
  if (!Array.isArray(d["cve_products"])) {
    throw new AttestdAPIError("Unexpected products response shape: missing 'cve_products'", 200);
  }
  if (!Array.isArray(d["supply_chain_packages"])) {
    throw new AttestdAPIError(
      "Unexpected products response shape: missing 'supply_chain_packages'",
      200
    );
  }
  if (typeof d["total"] !== "number") {
    throw new AttestdAPIError("Unexpected products response shape: missing 'total'", 200);
  }
  const cveProducts = d["cve_products"].flatMap((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [];
    const row = item;
    return [
      {
        slug: assertString(row["slug"], "slug"),
        displayName: assertString(row["display_name"], "display_name")
      }
    ];
  });
  const supplyChainPackages = d["supply_chain_packages"].flatMap((item) => {
    if (!item || typeof item !== "object" || Array.isArray(item)) return [];
    const row = item;
    return [
      {
        package: assertString(row["package"], "package"),
        ecosystem: assertString(row["ecosystem"], "ecosystem"),
        displayName: row["display_name"] != null ? assertString(row["display_name"], "display_name") : null
      }
    ];
  });
  return {
    cveProducts,
    supplyChainPackages,
    total: d["total"]
  };
}
function parseCveResponse(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new AttestdAPIError("Unexpected CVE response shape", 200);
  }
  const d = data;
  const affected = Array.isArray(d["affected_products"]) ? d["affected_products"].filter((x) => typeof x === "string") : [];
  return {
    cveId: assertString(d["cve_id"], "cve_id"),
    description: d["description"] != null ? assertString(d["description"], "description") : null,
    cvssScore: typeof d["cvss_score"] === "number" ? d["cvss_score"] : null,
    cvssVector: d["cvss_vector"] != null ? assertString(d["cvss_vector"], "cvss_vector") : null,
    activelyExploited: typeof d["actively_exploited"] === "boolean" ? d["actively_exploited"] : false,
    remoteExploitable: typeof d["remote_exploitable"] === "boolean" ? d["remote_exploitable"] : false,
    authenticationRequired: typeof d["authentication_required"] === "boolean" ? d["authentication_required"] : false,
    affectedProducts: affected,
    epssScore: typeof d["epss_score"] === "number" ? d["epss_score"] : null,
    epssPercentile: typeof d["epss_percentile"] === "number" ? d["epss_percentile"] : null,
    sourcePublishedAt: parseOptionalIso(d["source_published_at"], "source_published_at"),
    lastCheckedAt: parseOptionalIso(d["last_checked_at"], "last_checked_at")
  };
}
function parseUsageResponse(data) {
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new AttestdAPIError("Unexpected usage response shape", 200);
  }
  const d = data;
  const billingStart = parseOptionalIso(d["billing_period_start"], "billing_period_start");
  const billingEnd = parseOptionalIso(d["billing_period_end"], "billing_period_end");
  if (!billingStart || !billingEnd) {
    throw new AttestdAPIError("Unexpected usage response shape: missing billing period", 200);
  }
  return {
    tier: assertString(d["tier"], "tier"),
    keyCallsThisMonth: assertNumber(d["key_calls_this_month"], "key_calls_this_month"),
    accountCallsThisMonth: assertNumber(d["account_calls_this_month"], "account_calls_this_month"),
    includedCalls: assertNumber(d["included_calls"], "included_calls"),
    billingPeriodStart: billingStart,
    billingPeriodEnd: billingEnd,
    overageCalls: typeof d["overage_calls"] === "number" ? d["overage_calls"] : 0,
    estimatedOverageUsd: typeof d["estimated_overage_usd"] === "number" ? d["estimated_overage_usd"] : 0
  };
}

// src/version.ts
var VERSION = "0.6.0";

// src/client.ts
var Client = class {
  apiKey;
  baseUrl;
  timeout;
  maxRetries;
  retryDelayMs;
  fetchImpl;
  constructor(options = {}) {
    const env = typeof process !== "undefined" ? process.env : {};
    const apiKey = (options.apiKey ?? env.ATTESTD_API_KEY ?? "").trim();
    if (!apiKey) {
      throw new AttestdError(
        "attestd: apiKey is required. Pass it to Client() or set the ATTESTD_API_KEY environment variable."
      );
    }
    this.apiKey = apiKey;
    this.baseUrl = (options.baseUrl ?? env.ATTESTD_BASE_URL ?? DEFAULT_BASE_URL).replace(/\/$/, "");
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
        if (data && typeof data === "object" && !Array.isArray(data) && "supported" in data && data.supported === false) {
          const typosquat = parseTyposquat(data.typosquat ?? null);
          throw new AttestdUnsupportedProductError(product, version, typosquat);
        }
        return parseCheckResponse(data, product, version);
      }
      if (!RETRY_STATUS_CODES.has(response.status) || attempt === this.maxRetries) {
        const body = await response.text().catch(() => "");
        throw buildAttestdError(response.status, body, product, version, response.headers);
      }
      await response.text().catch(() => "");
      lastError = new AttestdAPIError(
        `Attestd API returned status ${response.status}`,
        response.status
      );
    }
    throw lastError ?? new AttestdAPIError("Unknown error", 0);
  }
  async checkBatch(items) {
    if (items.length === 0) return [];
    if (items.length > 100) {
      throw new AttestdError(
        `attestd: checkBatch accepts at most 100 items; got ${items.length}`
      );
    }
    const url = `${this.baseUrl}${BATCH_CHECK_PATH}`;
    let lastError = null;
    for (let attempt = 0; attempt <= this.maxRetries; attempt++) {
      if (attempt > 0) {
        await sleep(this.retryDelayMs * Math.pow(2, attempt - 1));
      }
      let response;
      try {
        response = await this.fetchImpl(url, {
          method: "POST",
          headers: {
            Authorization: `Bearer ${this.apiKey}`,
            "User-Agent": `attestd-js/${VERSION}`,
            Accept: "application/json",
            "Content-Type": "application/json"
          },
          body: JSON.stringify({ items }),
          signal: AbortSignal.timeout(this.timeout)
        });
      } catch (err) {
        const isTimeout = err instanceof Error && (err.name === "TimeoutError" || err.name === "AbortError");
        if (isTimeout) {
          throw new AttestdAPIError(`Request timed out after ${this.timeout}ms`, 0);
        }
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < this.maxRetries) continue;
        throw new AttestdAPIError(`Network error: ${lastError.message}`, 0);
      }
      if (response.ok) {
        let data;
        try {
          data = await response.json();
        } catch {
          throw new AttestdAPIError("Failed to parse Attestd batch API response as JSON", 200);
        }
        return parseBatchCheckResponse(data, items);
      }
      if (!RETRY_STATUS_CODES.has(response.status) || attempt === this.maxRetries) {
        const body = await response.text().catch(() => "");
        throw buildAttestdError(response.status, body, "", "", response.headers);
      }
      await response.text().catch(() => "");
      lastError = new AttestdAPIError(
        `Attestd API returned status ${response.status}`,
        response.status
      );
    }
    throw lastError ?? new AttestdAPIError("Unknown error", 0);
  }
  async products() {
    const data = await this.getWithRetry(PRODUCTS_PATH);
    return parseProductsResponse(data);
  }
  async cve(cveId) {
    const path = `${CVE_PATH_PREFIX}${encodeURIComponent(cveId.trim())}`;
    const data = await this.getWithRetry(path, { cveLookup: true });
    return parseCveResponse(data);
  }
  async usage() {
    const data = await this.getWithRetry(USAGE_PATH);
    return parseUsageResponse(data);
  }
  async getWithRetry(path, options = {}) {
    const url = `${this.baseUrl}${path}`;
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
          throw new AttestdAPIError(`Request timed out after ${this.timeout}ms`, 0);
        }
        lastError = err instanceof Error ? err : new Error(String(err));
        if (attempt < this.maxRetries) continue;
        throw new AttestdAPIError(`Network error: ${lastError.message}`, 0);
      }
      if (response.ok) {
        try {
          return await response.json();
        } catch {
          throw new AttestdAPIError("Failed to parse Attestd API response as JSON", 200);
        }
      }
      if (!RETRY_STATUS_CODES.has(response.status) || attempt === this.maxRetries) {
        const body = await response.text().catch(() => "");
        if (options.cveLookup && response.status === 404) {
          throw new AttestdAPIError("CVE not found", 404);
        }
        if (options.cveLookup && response.status === 400) {
          throw new AttestdAPIError("Invalid CVE id format (expected CVE-YYYY-NNNN)", 400);
        }
        throw buildAttestdError(response.status, body, "", "", response.headers);
      }
      await response.text().catch(() => "");
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