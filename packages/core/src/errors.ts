export type Pseud0WebLoginErrorCode =
  | "invalid_request"
  | "invalid_signature"
  | "domain_verification_failed"
  | "request_not_found"
  | "request_expired"
  | "request_denied"
  | "request_already_used"
  | "assertion_replayed"
  | "audience_mismatch"
  | "rate_limited"
  | "relay_unavailable"
  | "internal_error";

const MESSAGES: Readonly<Record<Pseud0WebLoginErrorCode, string>> = {
  invalid_request: "The request is invalid.",
  invalid_signature: "The signature is invalid.",
  domain_verification_failed: "Domain verification failed.",
  request_not_found: "The request was not found.",
  request_expired: "The request has expired.",
  request_denied: "The request was denied.",
  request_already_used: "The request has already been used.",
  assertion_replayed: "The assertion has already been used.",
  audience_mismatch: "The assertion audience does not match.",
  rate_limited: "Too many requests.",
  relay_unavailable: "The relay is unavailable.",
  internal_error: "An internal error occurred.",
};

export class WebLoginProtocolError extends Error {
  readonly code: Pseud0WebLoginErrorCode;

  constructor(code: Pseud0WebLoginErrorCode = "invalid_request") {
    super(MESSAGES[code]);
    this.name = "WebLoginProtocolError";
    this.code = code;
  }
}

export function invalidRequest(): never {
  throw new WebLoginProtocolError("invalid_request");
}
