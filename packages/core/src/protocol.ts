import { WebLoginProtocolError, invalidRequest } from "./errors.js";
import { canonicalizeJson, parseJsonStrict, type JsonValue } from "./json.js";
import {
  DOMAIN_PATTERN,
  KID_PATTERN,
  domainValue,
  integerValue,
  objectWithExactKeys,
  opaqueValue,
  publicKeyValue,
  signatureValue,
  stringValue,
  versionValue,
} from "./validation.js";

export const WEB_LOGIN_VERSION = 1 as const;
export const WEB_LOGIN_MAX_TTL_MS = 300_000 as const;
export const WEB_LOGIN_CLOCK_SKEW_MS = 30_000 as const;
export const WEB_LOGIN_MAX_QR_URI_LENGTH = 2_048 as const;
export const WEB_LOGIN_MAX_METADATA_BYTES = 16_384 as const;
export const WEB_LOGIN_RELAY_ORIGIN = "https://relay.pseud0.org" as const;
const textEncoder = new TextEncoder();

export interface SiteMetadata {
  version: 1;
  domain: string;
  displayName: string;
  publicKey: string;
  signature: string;
}

export interface SiteMetadataSigningPayload {
  displayName: string;
  domain: string;
  publicKey: string;
  version: 1;
}

export interface QrSigningPayload {
  domain: string;
  exp: number;
  iat: number;
  nonce: string;
  session: string;
  v: 1;
}

export interface ParsedQr extends QrSigningPayload {
  sig: string;
}

export interface RelayRegistration {
  version: 1;
  domain: string;
  sessionId: string;
  nonce: string;
  iat: number;
  exp: number;
  requestedDisplayName: string;
  qrSignature: string;
  registrationSignature: string;
}

export type RelayRegistrationSigningPayload = Omit<RelayRegistration, "registrationSignature">;

export interface RelayAssertion {
  version: 1;
  iss: typeof WEB_LOGIN_RELAY_ORIGIN;
  aud: string;
  sub: string;
  sessionId: string;
  nonce: string;
  jti: string;
  iat: number;
  nbf: number;
  exp: number;
  displayName: string;
  subjectKeyVersion: number;
  kid: string;
  signature: string;
}

export type RelayAssertionSigningPayload = Omit<RelayAssertion, "signature">;

export interface RelayRevocation {
  version: 1;
  iss: typeof WEB_LOGIN_RELAY_ORIGIN;
  aud: string;
  sub: string;
  jti: string;
  iat: number;
  exp: number;
  reason: string;
  kid: string;
  signature: string;
}

export type RelayRevocationSigningPayload = Omit<RelayRevocation, "signature">;

type JsonInput = unknown;

export function parseSiteMetadata(input: JsonInput): SiteMetadata {
  if (
    (input instanceof Uint8Array && input.byteLength > WEB_LOGIN_MAX_METADATA_BYTES) ||
    (typeof input === "string" &&
      textEncoder.encode(input).byteLength > WEB_LOGIN_MAX_METADATA_BYTES)
  ) {
    invalidRequest();
  }
  const object = objectWithExactKeys(toJson(input), [
    "version",
    "domain",
    "displayName",
    "publicKey",
    "signature",
  ]);
  return {
    version: versionValue(object.version),
    domain: domainValue(object.domain),
    displayName: stringValue(object.displayName, {
      min: 1,
      max: 100,
      nonBlank: true,
    }),
    publicKey: publicKeyValue(object.publicKey),
    signature: signatureValue(object.signature),
  };
}

export function buildSiteMetadataSigningPayload(
  metadata: SiteMetadataSigningPayload | SiteMetadata,
): SiteMetadataSigningPayload {
  return {
    displayName: stringValue(metadata.displayName, {
      min: 1,
      max: 100,
      nonBlank: true,
    }),
    domain: domainValue(metadata.domain),
    publicKey: publicKeyValue(metadata.publicKey),
    version: versionValue(metadata.version),
  };
}

export function canonicalizeSiteMetadata(
  metadata: SiteMetadataSigningPayload | SiteMetadata,
): string {
  return canonicalizeJson(buildSiteMetadataSigningPayload(metadata) as unknown as JsonValue);
}

export function buildQrSigningPayload(
  input: Omit<QrSigningPayload, "v"> & { v?: 1 },
): QrSigningPayload {
  const payload: QrSigningPayload = {
    domain: input.domain,
    exp: input.exp,
    iat: input.iat,
    nonce: input.nonce,
    session: input.session,
    v: input.v ?? WEB_LOGIN_VERSION,
  };
  validateQrPayload(payload);
  return payload;
}

export function canonicalizeQrSigningPayload(payload: QrSigningPayload): string {
  validateQrPayload(payload);
  return canonicalizeJson(payload as unknown as JsonValue);
}

export function buildQrUri(payload: QrSigningPayload, signature: string): string;
export function buildQrUri(payload: ParsedQr): string;
export function buildQrUri(payload: QrSigningPayload | ParsedQr, signature?: string): string {
  validateQrPayload(payload);
  const sig = signature ?? ("sig" in payload ? payload.sig : undefined);
  const validatedSignature = signatureValue(sig);
  const uri =
    `pseud0://web-login?v=1&domain=${payload.domain}` +
    `&session=${payload.session}&nonce=${payload.nonce}` +
    `&iat=${payload.iat}&exp=${payload.exp}&sig=${validatedSignature}`;
  if (uri.length > WEB_LOGIN_MAX_QR_URI_LENGTH) invalidRequest();
  return uri;
}

export function parseQrUri(value: string, scanTime?: number): ParsedQr {
  if (
    typeof value !== "string" ||
    value.length < 1 ||
    value.length > WEB_LOGIN_MAX_QR_URI_LENGTH ||
    /[%+\s#]/.test(value)
  ) {
    invalidRequest();
  }
  const match = /^pseud0:\/\/web-login\/?\?(.+)$/.exec(value);
  if (match === null) invalidRequest();
  const fields: Record<string, string> = {};
  for (const component of match[1]!.split("&")) {
    const separator = component.indexOf("=");
    if (
      separator <= 0 ||
      separator !== component.lastIndexOf("=") ||
      separator === component.length - 1
    ) {
      invalidRequest();
    }
    const key = component.slice(0, separator);
    if (Object.prototype.hasOwnProperty.call(fields, key)) invalidRequest();
    fields[key] = component.slice(separator + 1);
  }
  const expected = ["v", "domain", "session", "nonce", "iat", "exp", "sig"];
  if (
    Object.keys(fields).length !== expected.length ||
    expected.some((key) => !Object.prototype.hasOwnProperty.call(fields, key))
  ) {
    invalidRequest();
  }
  if (fields.v !== "1") invalidRequest();
  const iat = decimalInteger(fields.iat!);
  const exp = decimalInteger(fields.exp!);
  const payload = buildQrSigningPayload({
    domain: fields.domain!,
    session: fields.session!,
    nonce: fields.nonce!,
    iat,
    exp,
  });
  const result: ParsedQr = { ...payload, sig: signatureValue(fields.sig) };
  if (scanTime !== undefined) {
    const now = integerValue(scanTime as JsonValue);
    if (now < iat - WEB_LOGIN_CLOCK_SKEW_MS || now > exp) {
      throw new WebLoginProtocolError("request_expired");
    }
  }
  return result;
}

export function buildRelayRegistrationPayload(
  registration: RelayRegistrationSigningPayload | RelayRegistration,
): RelayRegistrationSigningPayload {
  const signingPayload: RelayRegistrationSigningPayload = {
    version: versionValue(registration.version),
    domain: domainValue(registration.domain),
    sessionId: opaqueValue(registration.sessionId),
    nonce: opaqueValue(registration.nonce),
    iat: integerValue(registration.iat, 0),
    exp: integerValue(registration.exp, 0),
    requestedDisplayName: stringValue(registration.requestedDisplayName, {
      max: 100,
    }),
    qrSignature: signatureValue(registration.qrSignature),
  };
  validateInterval(signingPayload.iat, signingPayload.exp);
  return signingPayload;
}

export function parseRelayRegistration(input: JsonInput): RelayRegistration {
  const object = objectWithExactKeys(toJson(input), [
    "version",
    "domain",
    "sessionId",
    "nonce",
    "iat",
    "exp",
    "requestedDisplayName",
    "qrSignature",
    "registrationSignature",
  ]);
  const result: RelayRegistration = {
    version: versionValue(object.version),
    domain: domainValue(object.domain),
    sessionId: opaqueValue(object.sessionId),
    nonce: opaqueValue(object.nonce),
    iat: integerValue(object.iat, 0),
    exp: integerValue(object.exp, 0),
    requestedDisplayName: stringValue(object.requestedDisplayName, { max: 100 }),
    qrSignature: signatureValue(object.qrSignature),
    registrationSignature: signatureValue(object.registrationSignature),
  };
  validateInterval(result.iat, result.exp);
  return result;
}

export function canonicalizeRelayRegistrationPayload(
  registration: RelayRegistrationSigningPayload | RelayRegistration,
): string {
  return canonicalizeJson(buildRelayRegistrationPayload(registration) as unknown as JsonValue);
}

export function parseRelayAssertion(input: JsonInput): RelayAssertion {
  const object = objectWithExactKeys(toJson(input), [
    "version",
    "iss",
    "aud",
    "sub",
    "sessionId",
    "nonce",
    "jti",
    "iat",
    "nbf",
    "exp",
    "displayName",
    "subjectKeyVersion",
    "kid",
    "signature",
  ]);
  const result: RelayAssertion = {
    version: versionValue(object.version),
    iss: relayIssuer(object.iss),
    aud: domainValue(object.aud),
    sub: publicKeyValue(object.sub),
    sessionId: opaqueValue(object.sessionId),
    nonce: opaqueValue(object.nonce),
    jti: opaqueValue(object.jti, 22),
    iat: integerValue(object.iat, 0),
    nbf: integerValue(object.nbf, 0),
    exp: integerValue(object.exp, 0),
    displayName: stringValue(object.displayName, {
      min: 1,
      max: 100,
      nonBlank: true,
    }),
    subjectKeyVersion: integerValue(object.subjectKeyVersion, 1),
    kid: stringValue(object.kid, { pattern: KID_PATTERN }),
    signature: signatureValue(object.signature),
  };
  validateInterval(result.iat, result.exp);
  if (result.nbf > result.exp) invalidRequest();
  return result;
}

export function buildRelayAssertionSigningPayload(
  assertion: RelayAssertion,
): RelayAssertionSigningPayload {
  const parsed = parseRelayAssertion(assertion as unknown as JsonValue);
  const { signature: _signature, ...payload } = parsed;
  return payload;
}

export function canonicalizeRelayAssertion(assertion: RelayAssertion): string {
  return canonicalizeJson(buildRelayAssertionSigningPayload(assertion) as unknown as JsonValue);
}

export function parseRelayRevocation(input: JsonInput): RelayRevocation {
  const object = objectWithExactKeys(toJson(input), [
    "version",
    "iss",
    "aud",
    "sub",
    "jti",
    "iat",
    "exp",
    "reason",
    "kid",
    "signature",
  ]);
  const result: RelayRevocation = {
    version: versionValue(object.version),
    iss: relayIssuer(object.iss),
    aud: domainValue(object.aud),
    sub: publicKeyValue(object.sub),
    jti: opaqueValue(object.jti, 22),
    iat: integerValue(object.iat, 0),
    exp: integerValue(object.exp, 0),
    reason: stringValue(object.reason, { max: 100 }),
    kid: stringValue(object.kid, { pattern: KID_PATTERN }),
    signature: signatureValue(object.signature),
  };
  validateInterval(result.iat, result.exp);
  return result;
}

export function buildRelayRevocationSigningPayload(
  revocation: RelayRevocation,
): RelayRevocationSigningPayload {
  const parsed = parseRelayRevocation(revocation as unknown as JsonValue);
  const { signature: _signature, ...payload } = parsed;
  return payload;
}

export function canonicalizeRelayRevocation(revocation: RelayRevocation): string {
  return canonicalizeJson(buildRelayRevocationSigningPayload(revocation) as unknown as JsonValue);
}

function validateQrPayload(payload: QrSigningPayload): void {
  if (
    payload.v !== WEB_LOGIN_VERSION ||
    !DOMAIN_PATTERN.test(payload.domain) ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(payload.session) ||
    !/^[A-Za-z0-9_-]{16,128}$/.test(payload.nonce) ||
    !Number.isSafeInteger(payload.iat) ||
    !Number.isSafeInteger(payload.exp)
  ) {
    invalidRequest();
  }
  validateInterval(payload.iat, payload.exp);
}

function validateInterval(iat: number, exp: number): void {
  if (exp <= iat || exp - iat > WEB_LOGIN_MAX_TTL_MS) invalidRequest();
}

function decimalInteger(value: string): number {
  if (!/^-?(?:0|[1-9]\d*)$/.test(value)) invalidRequest();
  const number = Number(value);
  if (!Number.isSafeInteger(number)) invalidRequest();
  return number;
}

function relayIssuer(value: JsonValue | undefined): typeof WEB_LOGIN_RELAY_ORIGIN {
  if (value !== WEB_LOGIN_RELAY_ORIGIN) invalidRequest();
  return WEB_LOGIN_RELAY_ORIGIN;
}

function toJson(input: JsonInput): JsonValue {
  return typeof input === "string" || input instanceof Uint8Array
    ? parseJsonStrict(input)
    : (input as JsonValue);
}
