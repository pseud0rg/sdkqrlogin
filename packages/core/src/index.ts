export {
  WEB_LOGIN_CLOCK_SKEW_MS,
  WEB_LOGIN_MAX_METADATA_BYTES,
  WEB_LOGIN_MAX_QR_URI_LENGTH,
  WEB_LOGIN_MAX_TTL_MS,
  WEB_LOGIN_RELAY_ORIGIN,
  WEB_LOGIN_VERSION,
  buildQrSigningPayload,
  buildQrUri,
  buildRelayAssertionSigningPayload,
  buildRelayRegistrationPayload,
  buildRelayRevocationSigningPayload,
  buildSiteMetadataSigningPayload,
  canonicalizeQrSigningPayload,
  canonicalizeRelayAssertion,
  canonicalizeRelayRegistrationPayload,
  canonicalizeRelayRevocation,
  canonicalizeSiteMetadata,
  parseQrUri,
  parseRelayAssertion,
  parseRelayRegistration,
  parseRelayRevocation,
  parseSiteMetadata,
  type ParsedQr,
  type QrSigningPayload,
  type RelayAssertion,
  type RelayAssertionSigningPayload,
  type RelayRegistration,
  type RelayRegistrationSigningPayload,
  type RelayRevocation,
  type RelayRevocationSigningPayload,
  type SiteMetadata,
  type SiteMetadataSigningPayload,
} from "./protocol.js";

export { WebLoginProtocolError, type Pseud0WebLoginErrorCode } from "./errors.js";

export { decodeBase64Url, encodeBase64Url, isCanonicalBase64Url } from "./base64url.js";

export { canonicalizeJson, parseJsonStrict, type JsonPrimitive, type JsonValue } from "./json.js";

export {
  DOMAIN_PATTERN,
  KID_PATTERN,
  OPAQUE_128_PATTERN,
  OPAQUE_PATTERN,
  domainValue,
  integerValue,
  objectWithExactKeys,
  opaqueValue,
  publicKeyValue,
  signatureValue,
  stringValue,
  versionValue,
} from "./validation.js";
