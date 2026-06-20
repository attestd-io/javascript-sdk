import type { TyposquatSignal } from './models.js';

export class AttestdError extends Error {
  constructor(message: string) {
    super(message);
    this.name = this.constructor.name;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown on 401 — invalid or missing API key. */
export class AttestdAuthError extends AttestdError {
  constructor(message = 'Invalid or missing API key') {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/** Thrown on 429 — rate limit exceeded. */
export class AttestdRateLimitError extends AttestdError {
  readonly retryAfter: number | null;

  constructor(message: string, retryAfter: number | null) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.retryAfter = retryAfter;
  }
}

/** Thrown on 404 — the product/version combination is outside Attestd's coverage. */
export class AttestdUnsupportedProductError extends AttestdError {
  readonly product: string;
  readonly version: string;
  readonly typosquat: TyposquatSignal | null;

  constructor(product: string, version: string, typosquat: TyposquatSignal | null = null) {
    super(
      `Product '${product}@${version}' is outside Attestd's coverage. ` +
        'This does not mean the product is safe. Attestd has no data for it. ' +
        'See https://attestd.io/docs/products for the full supported product list.',
    );
    Object.setPrototypeOf(this, new.target.prototype);
    this.product = product;
    this.version = version;
    this.typosquat = typosquat;
  }
}

/** Thrown on unexpected HTTP status codes, malformed responses, or transport failures. */
export class AttestdAPIError extends AttestdError {
  /** HTTP status code. 0 for network/transport failures and timeouts. */
  readonly statusCode: number;

  constructor(message: string, statusCode: number) {
    super(message);
    Object.setPrototypeOf(this, new.target.prototype);
    this.statusCode = statusCode;
  }
}
