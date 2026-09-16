import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  randomBytes,
  sign,
  type KeyObject,
} from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { resolve } from "node:path";
import { canonicalizeJson, type JsonValue } from "@pseud0/web-login-core";
import {
  createInMemoryWebLoginRepository,
  createPseud0WebLoginService,
  type RestrictedHttpClient,
} from "@pseud0/web-login-node";

const DOMAIN = "login.example.test";
const RELAY_ORIGIN = "https://relay.pseud0.org";
const RELAY_JWKS = `${RELAY_ORIGIN}/.well-known/jwks.json`;
const RELAY_KID = "local-development-only";

export interface ExampleUser {
  readonly id: string;
}

interface Registration {
  readonly sessionId: string;
  readonly nonce: string;
  readonly iat: number;
  readonly exp: number;
}

function developmentOnly(): void {
  if (process.env.NODE_ENV === "production") {
    throw new Error(
      "This example uses a fake relay and in-memory repository and is forbidden in production",
    );
  }
}

async function loadSiteKey(): Promise<KeyObject> {
  const configuredPath = process.env.PSEUD0_SITE_KEY_FILE;
  if (!configuredPath) {
    // A new in-memory key is generated for every development process. Nothing
    // secret is committed, persisted, printed, or copied into an environment variable.
    return generateKeyPairSync("ed25519").privateKey;
  }

  const path = resolve(configuredPath);
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink()) {
    throw new Error("PSEUD0_SITE_KEY_FILE must be a regular, non-symlink file");
  }
  if (process.platform !== "win32" && (metadata.mode & 0o077) !== 0) {
    throw new Error("PSEUD0_SITE_KEY_FILE must not be accessible by group or other users");
  }
  return createPrivateKey(await readFile(path));
}

function publicKeyBase64Url(privateKey: KeyObject): string {
  const jwk = createPublicKey(privateKey).export({ format: "jwk" });
  if (typeof jwk.x !== "string") throw new Error("Unable to export the Ed25519 public key");
  return jwk.x;
}

function createFakeRelay(): {
  readonly http: RestrictedHttpClient;
  approve(callbackOrigin: string): Promise<void>;
} {
  developmentOnly();
  const relayKey = generateKeyPairSync("ed25519");
  const relayJwk = relayKey.publicKey.export({ format: "jwk" });
  const registrations: Registration[] = [];
  const encode = (value: unknown): Uint8Array => Buffer.from(JSON.stringify(value), "utf8");

  const http: RestrictedHttpClient = {
    async request(request) {
      if (request.method === "GET" && request.url === RELAY_JWKS) {
        return {
          status: 200,
          headers: { "content-type": "application/json" },
          body: encode({
            keys: [
              {
                kty: "OKP",
                crv: "Ed25519",
                x: relayJwk.x,
                use: "sig",
                alg: "EdDSA",
                kid: RELAY_KID,
              },
            ],
          }),
        };
      }
      if (
        request.method === "POST" &&
        request.url === `${RELAY_ORIGIN}/v1/site-sessions` &&
        request.body
      ) {
        const body = JSON.parse(Buffer.from(request.body).toString("utf8")) as Registration;
        registrations.push({
          sessionId: body.sessionId,
          nonce: body.nonce,
          iat: body.iat,
          exp: body.exp,
        });
        return {
          status: 201,
          headers: { "content-type": "application/json" },
          body: encode({
            version: 1,
            sessionId: body.sessionId,
            status: "registered",
            expiresAt: body.exp,
          }),
        };
      }
      throw new Error("The development fake relay rejected an unexpected request");
    },
  };

  return {
    http,
    async approve(callbackOrigin) {
      const registration = registrations.at(-1);
      if (!registration) throw new Error("Create a browser login before simulating approval");
      const now = Date.now();
      const unsigned = {
        version: 1,
        iss: RELAY_ORIGIN,
        aud: DOMAIN,
        sub: randomBytes(32).toString("base64url"),
        sessionId: registration.sessionId,
        nonce: registration.nonce,
        jti: randomBytes(24).toString("base64url"),
        iat: now,
        nbf: now,
        exp: Math.min(registration.exp, now + 60_000),
        displayName: "Local development user",
        subjectKeyVersion: 1,
        kid: RELAY_KID,
      };
      const signature = sign(
        null,
        Buffer.from(canonicalizeJson(unsigned as unknown as JsonValue), "utf8"),
        relayKey.privateKey,
      ).toString("base64url");
      const response = await fetch(`${callbackOrigin}/pseud0/web-login/assertions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": unsigned.jti,
        },
        body: JSON.stringify({ ...unsigned, signature }),
      });
      if (!response.ok) throw new Error(`Fake relay callback failed with HTTP ${response.status}`);
    },
  };
}

export async function createExampleService<Response>(
  issueSession: (user: ExampleUser, response: Response) => Promise<void> | void,
) {
  developmentOnly();
  const siteKey = await loadSiteKey();
  const fakeRelay = createFakeRelay();
  const users = new Map<string, ExampleUser>();

  const service = await createPseud0WebLoginService<ExampleUser, Response>({
    config: {
      enabled: true,
      domain: DOMAIN,
      displayName: "pseud0 local example",
      relayOrigin: RELAY_ORIGIN,
      relayJwksUri: RELAY_JWKS,
      sitePrivateKey: siteKey,
      sitePublicKeyBase64Url: publicKeyBase64Url(siteKey),
      lookupPepper: randomBytes(32),
      dataEncryptionKey: randomBytes(32),
    },
    repository: createInMemoryWebLoginRepository({ testsOnly: true }),
    identities: {
      async findByPseud0Subject(subject) {
        return users.get(subject) ?? null;
      },
      async createFromPseud0({ subject }) {
        const user = { id: randomBytes(16).toString("base64url") };
        users.set(subject, user);
        return user;
      },
    },
    sessions: {
      async issueSession(user, response) {
        await issueSession(user, response);
      },
    },
    http: fakeRelay.http,
  });

  return { service, fakeRelay };
}
