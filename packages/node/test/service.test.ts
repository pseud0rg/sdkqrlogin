import { generateKeyPairSync, sign } from "node:crypto";
import { canonicalizeJson, type JsonValue } from "@pseud0/web-login-core";
import { describe, expect, it, vi } from "vitest";
import {
  Pseud0WebLoginError,
  createInMemoryWebLoginRepository,
  createPseud0WebLoginService,
  type RestrictedHttpClient,
  type SecureRandom,
} from "../src/index.js";

const b64 = (value: Uint8Array) => Buffer.from(value).toString("base64url");
const rawPublic = (key: ReturnType<typeof generateKeyPairSync>["publicKey"]) =>
  b64(key.export({ format: "der", type: "spki" }).subarray(-32));

class TestRandom implements SecureRandom {
  private counter = 1;
  bytes(length: number): Uint8Array {
    return Uint8Array.from({ length }, () => this.counter++ & 0xff);
  }
}

function headers(value: string) {
  return { get: (name: string) => (name.toLowerCase() === "idempotency-key" ? value : null) };
}

async function fixture() {
  const site = generateKeyPairSync("ed25519");
  const relay = generateKeyPairSync("ed25519");
  const relayJwk = relay.publicKey.export({ format: "jwk" });
  let now = 1_800_000_000_000;
  const calls: string[] = [];
  const http: RestrictedHttpClient = {
    async request(request) {
      calls.push(request.url);
      if (request.method === "GET") {
        return {
          status: 200,
          headers: { "content-type": "application/json" },
          body: Buffer.from(
            JSON.stringify({
              keys: [
                {
                  kty: "OKP",
                  crv: "Ed25519",
                  x: relayJwk.x,
                  use: "sig",
                  alg: "EdDSA",
                  kid: "relay-test",
                },
              ],
            }),
          ),
        };
      }
      const registration = JSON.parse(Buffer.from(request.body!).toString("utf8")) as {
        sessionId: string;
        exp: number;
      };
      return {
        status: 201,
        headers: { "content-type": "application/json" },
        body: Buffer.from(
          JSON.stringify({
            version: 1,
            sessionId: registration.sessionId,
            status: "registered",
            expiresAt: registration.exp,
          }),
        ),
      };
    },
  };
  const identities = {
    findByPseud0Subject: vi.fn(async () => null as { id: string } | null),
    createFromPseud0: vi.fn(async () => ({ id: "local-user" })),
    onSuccessfulLogin: vi.fn(async () => undefined),
    onRevocation: vi.fn(async () => undefined),
  };
  const sessions = {
    issueSession: vi.fn(async () => undefined),
    revokeSessions: vi.fn(async () => undefined),
  };
  const repository = createInMemoryWebLoginRepository({ testsOnly: true });
  const service = await createPseud0WebLoginService({
    config: {
      enabled: true,
      domain: "login.example.org",
      displayName: "Example",
      relayOrigin: "https://relay.pseud0.org",
      relayJwksUri: "https://relay.pseud0.org/.well-known/jwks.json",
      sitePrivateKey: site.privateKey,
      sitePublicKeyBase64Url: rawPublic(site.publicKey),
      lookupPepper: new Uint8Array(32).fill(7),
      dataEncryptionKey: new Uint8Array(32).fill(9),
    },
    repository,
    identities,
    sessions,
    http,
    clock: { now: () => now },
    random: new TestRandom(),
  });
  return {
    service,
    relay,
    calls,
    identities,
    sessions,
    setNow(value: number) {
      now = value;
    },
  };
}

describe("@pseud0/web-login-node", () => {
  it("fails closed when the configured Ed25519 pair does not match", async () => {
    const first = generateKeyPairSync("ed25519");
    const second = generateKeyPairSync("ed25519");
    await expect(
      createPseud0WebLoginService({
        config: {
          enabled: true,
          domain: "login.example.org",
          displayName: "Example",
          relayOrigin: "https://relay.pseud0.org",
          relayJwksUri: "https://relay.pseud0.org/.well-known/jwks.json",
          sitePrivateKey: first.privateKey,
          sitePublicKeyBase64Url: rawPublic(second.publicKey),
          lookupPepper: new Uint8Array(32),
          dataEncryptionKey: new Uint8Array(32),
        },
        repository: createInMemoryWebLoginRepository({ testsOnly: true }),
        identities: {
          findByPseud0Subject: async () => null,
          createFromPseud0: async () => ({}),
        },
        sessions: { issueSession: async () => undefined },
      }),
    ).rejects.toMatchObject({ code: "internal_error" });
  });

  it("registers with the relay before returning an exact QR", async () => {
    const { service, calls } = await fixture();
    const login = await service.createBrowserLogin({ origin: "https://login.example.org" });
    expect(calls).toEqual(["https://relay.pseud0.org/v1/site-sessions"]);
    expect(login.qr).toBe(
      `pseud0://web-login?v=1&domain=login.example.org&session=${login.session}` +
        `&nonce=${login.qr.split("&nonce=")[1]!.split("&")[0]}` +
        `&iat=1800000000000&exp=1800000300000&sig=${login.qr.split("&sig=")[1]}`,
    );
    await expect(service.status(login.session, login.browser_secret)).resolves.toMatchObject({
      status: "pending",
    });
    await expect(service.status(login.session, "A".repeat(43))).rejects.toMatchObject({
      code: "request_not_found",
    });
  });

  it("verifies, stores once, completes once, and invokes site callbacks", async () => {
    const { service, relay, identities, sessions } = await fixture();
    const login = await service.createBrowserLogin({});
    const nonce = login.qr.split("&nonce=")[1]!.split("&")[0]!;
    const assertion = {
      version: 1,
      iss: "https://relay.pseud0.org",
      aud: "login.example.org",
      sub: b64(new Uint8Array(32).fill(4)),
      sessionId: login.session,
      nonce,
      jti: b64(new Uint8Array(20).fill(5)),
      iat: 1_800_000_000_100,
      nbf: 1_800_000_000_100,
      exp: login.exp,
      displayName: "Alice",
      subjectKeyVersion: 1,
      kid: "relay-test",
    };
    const signature = sign(
      null,
      Buffer.from(canonicalizeJson(assertion as unknown as JsonValue)),
      relay.privateKey,
    ).toString("base64url");
    const raw = Buffer.from(JSON.stringify({ ...assertion, signature }));
    await expect(service.acceptAssertion(raw, headers(assertion.jti))).resolves.toMatchObject({
      status: "accepted",
    });
    await expect(service.acceptAssertion(raw, headers(assertion.jti))).resolves.toMatchObject({
      status: "already_accepted",
    });
    await expect(
      service.complete(login.session, login.browser_secret, {}),
    ).resolves.toBeUndefined();
    expect(identities.createFromPseud0).toHaveBeenCalledOnce();
    expect(sessions.issueSession).toHaveBeenCalledOnce();
    await expect(service.complete(login.session, login.browser_secret, {})).rejects.toMatchObject({
      code: "request_already_used",
    });
  });

  it("rejects duplicate callback keys before JWKS or persistence", async () => {
    const { service, calls } = await fixture();
    const raw = Buffer.from('{"version":1,"version":1}');
    await expect(service.acceptAssertion(raw, headers("A".repeat(22)))).rejects.toBeInstanceOf(
      Pseud0WebLoginError,
    );
    expect(calls).toEqual([]);
  });
});
