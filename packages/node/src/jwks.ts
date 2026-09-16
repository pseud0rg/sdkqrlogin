import { verify, type KeyObject } from "node:crypto";
import { decodeBase64Url, importEd25519Jwk } from "./crypto.js";
import { assertExactKeys, canonicalize, parseStrictJson } from "./strict-json.js";
import { Pseud0WebLoginError, type Clock, type RestrictedHttpClient } from "./types.js";

interface CachedKey {
  key: KeyObject;
  expiresAt: number;
}

export class RelayJwksCache {
  private readonly keys = new Map<string, CachedKey>();
  private lastUnknownKidRefresh = 0;

  public constructor(
    private readonly uri: string,
    private readonly http: RestrictedHttpClient,
    private readonly clock: Clock,
  ) {}

  public async verify(kid: string, signature: string, payload: object): Promise<void> {
    let key = this.get(kid);
    if (!key) {
      const now = this.clock.now();
      if (now - this.lastUnknownKidRefresh < 1_000 && this.lastUnknownKidRefresh !== 0) {
        throw new Pseud0WebLoginError("invalid_signature");
      }
      this.lastUnknownKidRefresh = now;
      await this.refresh();
      key = this.get(kid);
    }
    if (!key) throw new Pseud0WebLoginError("invalid_signature");
    let bytes: Uint8Array;
    try {
      bytes = decodeBase64Url(signature, 64);
    } catch {
      throw new Pseud0WebLoginError("invalid_signature");
    }
    if (!verify(null, Buffer.from(canonicalize(payload), "utf8"), key, bytes)) {
      throw new Pseud0WebLoginError("invalid_signature");
    }
  }

  private get(kid: string): KeyObject | undefined {
    const entry = this.keys.get(kid);
    if (!entry || entry.expiresAt <= this.clock.now()) {
      this.keys.delete(kid);
      return undefined;
    }
    return entry.key;
  }

  private async refresh(): Promise<void> {
    const response = await this.http.request({
      method: "GET",
      url: this.uri,
      expectedContentTypes: ["application/json"],
      maxResponseBytes: 16_384,
    });
    if (response.status !== 200) throw new Pseud0WebLoginError("relay_unavailable", true);
    const document = parseStrictJson(response.body);
    assertExactKeys(document, ["keys"]);
    if (!Array.isArray(document.keys) || document.keys.length === 0 || document.keys.length > 20) {
      throw new Pseud0WebLoginError("invalid_signature");
    }
    const expiresAt = this.clock.now() + 300_000;
    const next = new Map<string, CachedKey>();
    for (const item of document.keys) {
      assertExactKeys(item, ["kty", "crv", "x", "use", "alg", "kid"]);
      if (
        item.kty !== "OKP" ||
        item.crv !== "Ed25519" ||
        item.use !== "sig" ||
        item.alg !== "EdDSA" ||
        typeof item.kid !== "string" ||
        !/^[A-Za-z0-9._-]{1,64}$/.test(item.kid) ||
        typeof item.x !== "string"
      ) {
        throw new Pseud0WebLoginError("invalid_signature");
      }
      decodeBase64Url(item.x, 32);
      if (next.has(item.kid)) throw new Pseud0WebLoginError("invalid_signature");
      next.set(item.kid, {
        key: importEd25519Jwk({
          kty: "OKP",
          crv: "Ed25519",
          x: item.x,
        }),
        expiresAt,
      });
    }
    this.keys.clear();
    for (const [kid, entry] of next) this.keys.set(kid, entry);
  }
}
