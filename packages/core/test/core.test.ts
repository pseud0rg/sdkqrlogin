import { describe, expect, it } from "vitest";
import {
  WebLoginProtocolError,
  buildQrSigningPayload,
  buildQrUri,
  canonicalizeJson,
  canonicalizeQrSigningPayload,
  canonicalizeRelayAssertion,
  canonicalizeRelayRegistrationPayload,
  canonicalizeRelayRevocation,
  canonicalizeSiteMetadata,
  decodeBase64Url,
  encodeBase64Url,
  parseJsonStrict,
  parseQrUri,
  parseRelayAssertion,
  parseRelayRevocation,
  parseSiteMetadata,
  type RelayAssertion,
  type RelayRegistration,
  type RelayRevocation,
  type SiteMetadata,
} from "../src/index.js";

const publicKey = encodeBase64Url(new Uint8Array(32));
const signature = encodeBase64Url(new Uint8Array(64));
const opaque = "A".repeat(22);
const session = "session_123456789";
const nonce = "nonce_12345678901";

const metadata: SiteMetadata = {
  version: 1,
  domain: "login.example.org",
  displayName: "Example",
  publicKey,
  signature,
};

describe("strict JSON and RFC 8785", () => {
  it("matches the RFC 8785 canonicalization sample", () => {
    expect(
      canonicalizeJson({
        numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 1e-27],
        string: '€$\u000f\nA\'B"\\\\"/',
        literals: [null, true, false],
      }),
    ).toBe(
      '{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}',
    );
  });

  it("rejects invalid UTF-8 and duplicate decoded keys", () => {
    expect(() => parseJsonStrict(Uint8Array.of(0xc3, 0x28))).toThrow(WebLoginProtocolError);
    expect(() => parseJsonStrict('{"a":1,"\\u0061":2}')).toThrow(WebLoginProtocolError);
  });

  it("rejects lone Unicode surrogates for JCS", () => {
    expect(() => canonicalizeJson("\ud800")).toThrow(WebLoginProtocolError);
  });
});

describe("canonical base64url", () => {
  it("round-trips deterministic bytes without padding", () => {
    const bytes = Uint8Array.of(0xfb, 0xff, 0);
    expect(encodeBase64Url(bytes)).toBe("-_8A");
    expect(decodeBase64Url("-_8A")).toEqual(bytes);
  });

  it("rejects padding and non-zero trailing bits", () => {
    expect(() => decodeBase64Url("AA==")).toThrow(WebLoginProtocolError);
    expect(() => decodeBase64Url("AB")).toThrow(WebLoginProtocolError);
  });
});

describe("metadata", () => {
  it("produces the exact signed JCS object", () => {
    expect(canonicalizeSiteMetadata(metadata)).toBe(
      `{"displayName":"Example","domain":"login.example.org","publicKey":"${publicKey}","version":1}`,
    );
  });

  it("strictly parses bytes and rejects unknown fields", () => {
    expect(parseSiteMetadata(new TextEncoder().encode(JSON.stringify(metadata)))).toEqual(metadata);
    expect(() => parseSiteMetadata(JSON.stringify({ ...metadata, endpoint: "x" }))).toThrow(
      WebLoginProtocolError,
    );
  });
});

describe("QR", () => {
  const payload = buildQrSigningPayload({
    domain: "login.example.org",
    session,
    nonce,
    iat: 1_800_000_000_000,
    exp: 1_800_000_300_000,
  });

  it("matches the protocol signing and URI vectors", () => {
    expect(canonicalizeQrSigningPayload(payload)).toBe(
      `{"domain":"login.example.org","exp":1800000300000,"iat":1800000000000,"nonce":"${nonce}","session":"${session}","v":1}`,
    );
    const uri = buildQrUri(payload, signature);
    expect(uri).toBe(
      `pseud0://web-login?v=1&domain=login.example.org&session=${session}&nonce=${nonce}&iat=1800000000000&exp=1800000300000&sig=${signature}`,
    );
    expect(parseQrUri(uri, 1_800_000_000_000)).toEqual({
      ...payload,
      sig: signature,
    });
  });

  it("rejects duplicate, escaped, expired and overlong TTL values", () => {
    const uri = buildQrUri(payload, signature);
    expect(() => parseQrUri(`${uri}&v=1`)).toThrow(WebLoginProtocolError);
    expect(() => parseQrUri(uri.replace("login.example.org", "login%2Eexample.org"))).toThrow(
      WebLoginProtocolError,
    );
    expect(() => parseQrUri(uri, payload.exp + 1)).toThrow(
      expect.objectContaining({ code: "request_expired" }),
    );
    expect(() => buildQrSigningPayload({ ...payload, exp: payload.exp + 1 })).toThrow(
      WebLoginProtocolError,
    );
  });
});

describe("relay signed objects", () => {
  const registration: RelayRegistration = {
    version: 1,
    domain: "login.example.org",
    sessionId: session,
    nonce,
    iat: 1_800_000_000_000,
    exp: 1_800_000_300_000,
    requestedDisplayName: "Alice",
    qrSignature: signature,
    registrationSignature: signature,
  };

  const assertion: RelayAssertion = {
    version: 1,
    iss: "https://relay.pseud0.org",
    aud: "login.example.org",
    sub: publicKey,
    sessionId: session,
    nonce,
    jti: opaque,
    iat: 1_800_000_000_001,
    nbf: 1_800_000_000_001,
    exp: 1_800_000_300_000,
    displayName: "Alice",
    subjectKeyVersion: 1,
    kid: "relay-2026-01",
    signature,
  };

  const revocation: RelayRevocation = {
    version: 1,
    iss: "https://relay.pseud0.org",
    aud: "login.example.org",
    sub: publicKey,
    jti: opaque,
    iat: 1_800_000_100_000,
    exp: 1_800_000_200_000,
    reason: "user_requested",
    kid: "relay-2026-01",
    signature,
  };

  it("builds the deterministic registration signing vector", () => {
    const { registrationSignature: _registrationSignature, ...unsigned } = registration;
    expect(canonicalizeRelayRegistrationPayload(unsigned)).toBe(
      `{"domain":"login.example.org","exp":1800000300000,"iat":1800000000000,"nonce":"${nonce}","qrSignature":"${signature}","requestedDisplayName":"Alice","sessionId":"${session}","version":1}`,
    );
  });

  it("parses and canonicalizes assertion without its signature", () => {
    expect(parseRelayAssertion(JSON.stringify(assertion))).toEqual(assertion);
    const canonical = canonicalizeRelayAssertion(assertion);
    expect(canonical).not.toContain('"signature"');
    expect(canonical).toBe(
      `{"aud":"login.example.org","displayName":"Alice","exp":1800000300000,"iat":1800000000001,"iss":"https://relay.pseud0.org","jti":"${opaque}","kid":"relay-2026-01","nbf":1800000000001,"nonce":"${nonce}","sessionId":"${session}","sub":"${publicKey}","subjectKeyVersion":1,"version":1}`,
    );
  });

  it("parses and canonicalizes revocation without its signature", () => {
    expect(parseRelayRevocation(JSON.stringify(revocation))).toEqual(revocation);
    expect(canonicalizeRelayRevocation(revocation)).toBe(
      `{"aud":"login.example.org","exp":1800000200000,"iat":1800000100000,"iss":"https://relay.pseud0.org","jti":"${opaque}","kid":"relay-2026-01","reason":"user_requested","sub":"${publicKey}","version":1}`,
    );
  });

  it("rejects wrong issuer, non-integers and unknown fields", () => {
    expect(() =>
      parseRelayAssertion(JSON.stringify({ ...assertion, iss: "https://evil.example" })),
    ).toThrow(WebLoginProtocolError);
    expect(() => parseRelayAssertion(JSON.stringify({ ...assertion, iat: 1.5 }))).toThrow(
      WebLoginProtocolError,
    );
    expect(() => parseRelayRevocation(JSON.stringify({ ...revocation, extra: true }))).toThrow(
      WebLoginProtocolError,
    );
  });
});

describe("stable errors", () => {
  it("does not expose rejected input", () => {
    const secret = "sensitive-value";
    try {
      parseSiteMetadata(secret);
      throw new Error("unreachable");
    } catch (error) {
      expect(error).toBeInstanceOf(WebLoginProtocolError);
      expect((error as WebLoginProtocolError).code).toBe("invalid_request");
      expect((error as Error).message).not.toContain(secret);
    }
  });
});
