import {
  createCipheriv,
  createDecipheriv,
  createHash,
  createHmac,
  createPublicKey,
  KeyObject,
  randomBytes,
  sign,
  timingSafeEqual,
  verify,
  type JsonWebKey,
} from "node:crypto";
import { canonicalizeJson, type JsonValue } from "@pseud0/web-login-core";
import { Pseud0WebLoginError, type SecureRandom, type SitePrivateKey } from "./types.js";

const B64URL = /^[A-Za-z0-9_-]+$/;

export function encodeBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

export function decodeBase64Url(value: string, expectedLength?: number): Uint8Array {
  if (!value || value.includes("=") || !B64URL.test(value)) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  const bytes = Buffer.from(value, "base64url");
  if (
    encodeBase64Url(bytes) !== value ||
    (expectedLength !== undefined && bytes.length !== expectedLength)
  ) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  return bytes;
}

export function hmac(pepper: Uint8Array, context: string, value: string | Uint8Array): Uint8Array {
  return createHmac("sha256", pepper)
    .update(`pseud0-web-login-v1\0${context}\0`, "utf8")
    .update(value)
    .digest();
}

export function hashBody(bytes: Uint8Array): Uint8Array {
  return createHash("sha256").update(bytes).digest();
}

export function equalBytes(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && timingSafeEqual(a, b);
}

export function encrypt(
  key: Uint8Array,
  type: string,
  plaintext: string,
  random: SecureRandom,
): Uint8Array {
  const iv = random.bytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  cipher.setAAD(Buffer.from(`pseud0-web-login-v1\0${type}`, "utf8"));
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), encrypted]);
}

export function decrypt(key: Uint8Array, type: string, value: Uint8Array): string {
  if (value.length < 28) throw new Pseud0WebLoginError("internal_error");
  try {
    const decipher = createDecipheriv("aes-256-gcm", key, value.subarray(0, 12));
    decipher.setAAD(Buffer.from(`pseud0-web-login-v1\0${type}`, "utf8"));
    decipher.setAuthTag(value.subarray(12, 28));
    return decipher.update(value.subarray(28), undefined, "utf8") + decipher.final("utf8");
  } catch {
    throw new Pseud0WebLoginError("internal_error");
  }
}

export async function loadAndVerifySiteKey(
  source: SitePrivateKey,
  configuredPublic: string,
): Promise<KeyObject> {
  const loaded = typeof source === "function" ? await source() : source;
  const privateKey =
    loaded instanceof KeyObject
      ? loaded
      : KeyObject.from(loaded as Parameters<typeof KeyObject.from>[0]);
  const expected = decodeBase64Url(configuredPublic, 32);
  let publicKey: KeyObject;
  try {
    publicKey = createPublicKey(privateKey);
    const der = publicKey.export({ format: "der", type: "spki" });
    const raw = new Uint8Array(der.subarray(-32));
    if (!equalBytes(raw, expected)) throw new Error("mismatch");
    const probe = Buffer.from("pseud0-web-login-site-key-self-test-v1", "utf8");
    if (!verify(null, probe, publicKey, sign(null, probe, privateKey)))
      throw new Error("self-test");
  } catch {
    throw new Pseud0WebLoginError("internal_error");
  }
  return privateKey;
}

export function signObject(privateKey: KeyObject, value: object): string {
  return sign(
    null,
    Buffer.from(canonicalizeJson(value as unknown as JsonValue), "utf8"),
    privateKey,
  ).toString("base64url");
}

export const nodeRandom: SecureRandom = {
  bytes(length) {
    return randomBytes(length);
  },
};

export function importEd25519Jwk(jwk: JsonWebKey): KeyObject {
  try {
    return createPublicKey({ key: jwk, format: "jwk" });
  } catch {
    throw new Pseud0WebLoginError("invalid_signature");
  }
}
