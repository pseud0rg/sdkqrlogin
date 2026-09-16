import { createPublicKey, verify } from "node:crypto";
import { readFile } from "node:fs/promises";
import {
  buildQrSigningPayload,
  buildQrUri,
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
  type RelayAssertion,
  type RelayRegistration,
  type RelayRevocation,
  type SiteMetadata,
} from "@pseud0/web-login-core";
import { describe, expect, it } from "vitest";

interface Vectors {
  publicKey: string;
  metadata: SiteMetadata;
  qr: {
    v: 1;
    domain: string;
    session: string;
    nonce: string;
    iat: number;
    exp: number;
    sig: string;
  };
  registration: RelayRegistration;
  assertion: RelayAssertion;
  revocation: RelayRevocation;
}

const vectorUrl = new URL("../../../test-vectors/web-login-v1.json", import.meta.url);
const canonicalUrl = new URL("../../../test-vectors/web-login-v1-canonical.txt", import.meta.url);
const qrUrl = new URL("../../../test-vectors/web-login-v1-qr.txt", import.meta.url);

async function load(): Promise<{
  vectors: Vectors;
  canonical: Record<string, string>;
  qr: string;
}> {
  const [json, text, qr] = await Promise.all([
    readFile(vectorUrl, "utf8"),
    readFile(canonicalUrl, "utf8"),
    readFile(qrUrl, "utf8"),
  ]);
  const canonical = Object.fromEntries(
    text
      .split(/\r?\n/u)
      .slice(1)
      .filter(Boolean)
      .map((line) => {
        const separator = line.indexOf("\t");
        return [line.slice(0, separator), line.slice(separator + 1)];
      }),
  );
  return {
    vectors: JSON.parse(json) as Vectors,
    canonical,
    qr: qr.trim(),
  };
}

function publicKey(raw: string) {
  return createPublicKey({
    key: Buffer.concat([
      Buffer.from("302a300506032b6570032100", "hex"),
      Buffer.from(raw, "base64url"),
    ]),
    format: "der",
    type: "spki",
  });
}

const verifies = (payload: string, signature: string, key: ReturnType<typeof publicKey>): boolean =>
  verify(null, Buffer.from(payload), key, Buffer.from(signature, "base64url"));

describe("public deterministic web-login vectors", () => {
  it("matches every JSON object to its exact text JCS payload", async () => {
    const { vectors, canonical } = await load();
    expect(canonicalizeSiteMetadata(vectors.metadata)).toBe(canonical.metadata);
    expect(
      canonicalizeQrSigningPayload(
        buildQrSigningPayload({
          domain: vectors.qr.domain,
          session: vectors.qr.session,
          nonce: vectors.qr.nonce,
          iat: vectors.qr.iat,
          exp: vectors.qr.exp,
        }),
      ),
    ).toBe(canonical.qr);
    const { registrationSignature: _registrationSignature, ...registration } = vectors.registration;
    expect(canonicalizeRelayRegistrationPayload(registration)).toBe(canonical.registration);
    expect(canonicalizeRelayAssertion(vectors.assertion)).toBe(canonical.assertion);
    expect(canonicalizeRelayRevocation(vectors.revocation)).toBe(canonical.revocation);
  });

  it("parses every complete signed JSON object strictly", async () => {
    const { vectors } = await load();
    expect(parseSiteMetadata(JSON.stringify(vectors.metadata))).toEqual(vectors.metadata);
    expect(parseRelayRegistration(JSON.stringify(vectors.registration))).toEqual(
      vectors.registration,
    );
    expect(parseRelayAssertion(JSON.stringify(vectors.assertion))).toEqual(vectors.assertion);
    expect(parseRelayRevocation(JSON.stringify(vectors.revocation))).toEqual(vectors.revocation);
  });

  it("verifies all Ed25519 signatures and rejects one-bit changes", async () => {
    const { vectors, canonical } = await load();
    const key = publicKey(vectors.publicKey);
    const entries = [
      [canonical.metadata, vectors.metadata.signature],
      [canonical.qr, vectors.qr.sig],
      [canonical.registration, vectors.registration.registrationSignature],
      [canonical.assertion, vectors.assertion.signature],
      [canonical.revocation, vectors.revocation.signature],
    ] as const;

    for (const [payload, signature] of entries) {
      expect(verifies(payload, signature, key)).toBe(true);
      const changed = Buffer.from(signature, "base64url");
      changed[0] = changed[0]! ^ 1;
      expect(verify(null, Buffer.from(payload), key, changed)).toBe(false);
    }
  });

  it("matches the Android wire text and expiry/skew boundaries", async () => {
    const { vectors, qr } = await load();
    const payload = buildQrSigningPayload({
      domain: vectors.qr.domain,
      session: vectors.qr.session,
      nonce: vectors.qr.nonce,
      iat: vectors.qr.iat,
      exp: vectors.qr.exp,
    });
    expect(buildQrUri(payload, vectors.qr.sig)).toBe(qr);
    expect(parseQrUri(qr, vectors.qr.iat - 30_000)).toMatchObject(payload);
    expect(parseQrUri(qr, vectors.qr.exp)).toMatchObject(payload);
    expect(() => parseQrUri(qr, vectors.qr.iat - 30_001)).toThrow();
    expect(() => parseQrUri(qr, vectors.qr.exp + 1)).toThrow();
  });

  it("rejects non-canonical base64url and unknown or duplicate fields", async () => {
    const { vectors, qr } = await load();
    expect(() => parseQrUri(qr.replace(vectors.qr.sig, `${vectors.qr.sig}=`))).toThrow();
    expect(() =>
      parseSiteMetadata(JSON.stringify({ ...vectors.metadata, endpoint: "test-only" })),
    ).toThrow();
    expect(() =>
      parseRelayAssertion(`{"version":1,"version":1,${JSON.stringify(vectors.assertion).slice(1)}`),
    ).toThrow();
  });
});
