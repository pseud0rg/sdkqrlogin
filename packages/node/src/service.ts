import {
  DOMAIN_PATTERN,
  WEB_LOGIN_CLOCK_SKEW_MS,
  WEB_LOGIN_MAX_TTL_MS,
  WEB_LOGIN_RELAY_ORIGIN,
  buildQrSigningPayload,
  buildQrUri,
} from "@pseud0/web-login-core";
import {
  decodeBase64Url,
  decrypt,
  encodeBase64Url,
  encrypt,
  equalBytes,
  hashBody,
  hmac,
  loadAndVerifySiteKey,
  nodeRandom,
  signObject,
} from "./crypto.js";
import { createRestrictedHttpClient } from "./http.js";
import { RelayJwksCache } from "./jwks.js";
import { assertExactKeys, parseStrictJson } from "./strict-json.js";
import {
  Pseud0WebLoginError,
  type CreateLoginResult,
  type HeadersLike,
  type LoginState,
  type Pseud0WebLoginErrorCode,
  type Pseud0WebLoginService,
  type Pseud0WebLoginServiceOptions,
  type PublicLoginStatus,
  type RelayCallbackResult,
  type RestrictedHttpClient,
  type SiteMetadata,
  type WebLoginRequestRecord,
} from "./types.js";

const OPAQUE = /^[A-Za-z0-9_-]{22,128}$/;
const SESSION = /^[A-Za-z0-9_-]{16,128}$/;
const KID = /^[A-Za-z0-9._-]{1,64}$/;
const ISSUER = WEB_LOGIN_RELAY_ORIGIN;
const MAX_TTL = WEB_LOGIN_MAX_TTL_MS;

interface RelayAssertion {
  version: 1;
  iss: string;
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

interface RelayRevocation {
  version: 1;
  iss: string;
  aud: string;
  sub: string;
  jti: string;
  iat: number;
  exp: number;
  reason: string;
  kid: string;
  signature: string;
}

function integer(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function signature(value: unknown): value is string {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(value)) return false;
  try {
    decodeBase64Url(value, 64);
    return true;
  } catch {
    return false;
  }
}

function parseAssertion(raw: Uint8Array): RelayAssertion {
  const value = parseStrictJson(raw);
  assertExactKeys(value, [
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
  if (
    value.version !== 1 ||
    typeof value.iss !== "string" ||
    typeof value.aud !== "string" ||
    typeof value.sub !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.sub) ||
    typeof value.sessionId !== "string" ||
    !SESSION.test(value.sessionId) ||
    typeof value.nonce !== "string" ||
    !OPAQUE.test(value.nonce) ||
    typeof value.jti !== "string" ||
    !OPAQUE.test(value.jti) ||
    !integer(value.iat) ||
    !integer(value.nbf) ||
    !integer(value.exp) ||
    typeof value.displayName !== "string" ||
    value.displayName.length < 1 ||
    value.displayName.length > 100 ||
    !integer(value.subjectKeyVersion) ||
    value.subjectKeyVersion < 1 ||
    typeof value.kid !== "string" ||
    !KID.test(value.kid) ||
    !signature(value.signature)
  )
    throw new Pseud0WebLoginError("invalid_request");
  return value as unknown as RelayAssertion;
}

function parseRevocation(raw: Uint8Array): RelayRevocation {
  const value = parseStrictJson(raw);
  assertExactKeys(value, [
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
  if (
    value.version !== 1 ||
    typeof value.iss !== "string" ||
    typeof value.aud !== "string" ||
    typeof value.sub !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(value.sub) ||
    typeof value.jti !== "string" ||
    !OPAQUE.test(value.jti) ||
    !integer(value.iat) ||
    !integer(value.exp) ||
    typeof value.reason !== "string" ||
    value.reason.length > 100 ||
    typeof value.kid !== "string" ||
    !KID.test(value.kid) ||
    !signature(value.signature)
  )
    throw new Pseud0WebLoginError("invalid_request");
  return value as unknown as RelayRevocation;
}

function withoutSignature<T extends { signature: string }>(value: T): Omit<T, "signature"> {
  const { signature: ignored, ...payload } = value;
  void ignored;
  return payload;
}

function validateTimes(
  value: { iat: number; nbf?: number; exp: number },
  now: number,
  skew: number,
): void {
  const nbf = value.nbf ?? value.iat;
  if (
    value.exp <= value.iat ||
    value.exp - value.iat > MAX_TTL ||
    nbf < value.iat ||
    nbf > value.exp ||
    value.iat > now + skew ||
    nbf > now + skew ||
    value.exp < now - skew
  ) {
    throw new Pseud0WebLoginError("request_expired");
  }
}

function publicStatus(state: LoginState): PublicLoginStatus["status"] {
  switch (state) {
    case "registering":
    case "registered":
      return "pending";
    case "assertion_received":
      return "ready";
    case "consumed":
      return "consumed";
    case "denied":
      return "denied";
    case "expired":
      return "expired";
    case "cancelled":
      return "cancelled";
  }
}

function validateConfig(config: Pseud0WebLoginServiceOptions<unknown, unknown>["config"]): {
  ttl: number;
  skew: number;
  relayOrigin: string;
} {
  if (!config.enabled) throw new Pseud0WebLoginError("internal_error");
  if (!DOMAIN_PATTERN.test(config.domain)) throw new Pseud0WebLoginError("internal_error");
  if (!config.displayName.trim() || config.displayName.length > 100) {
    throw new Pseud0WebLoginError("internal_error");
  }
  const ttl = config.requestTtlMs ?? MAX_TTL;
  const skew = config.allowedClockSkewMs ?? WEB_LOGIN_CLOCK_SKEW_MS;
  if (
    !Number.isInteger(ttl) ||
    ttl < 1 ||
    ttl > MAX_TTL ||
    !Number.isInteger(skew) ||
    skew < 0 ||
    skew > WEB_LOGIN_CLOCK_SKEW_MS
  ) {
    throw new Pseud0WebLoginError("internal_error");
  }
  if (config.lookupPepper.length < 32 || config.dataEncryptionKey.length !== 32) {
    throw new Pseud0WebLoginError("internal_error");
  }
  try {
    const relay = new URL(config.relayOrigin);
    const jwks = new URL(config.relayJwksUri);
    if (
      relay.protocol !== "https:" ||
      relay.username ||
      relay.password ||
      relay.port ||
      relay.pathname !== "/" ||
      relay.search ||
      relay.hash ||
      jwks.protocol !== "https:" ||
      jwks.origin !== relay.origin ||
      jwks.username ||
      jwks.password ||
      jwks.port ||
      jwks.hash
    )
      throw new Error("invalid");
    return { ttl, skew, relayOrigin: relay.origin };
  } catch {
    throw new Pseud0WebLoginError("internal_error");
  }
}

async function safeAudit(
  options: Pseud0WebLoginServiceOptions<unknown, unknown>,
  type: Parameters<NonNullable<typeof options.audit>["record"]>[0]["type"],
  at: number,
  code?: Pseud0WebLoginErrorCode,
): Promise<void> {
  try {
    await options.audit?.record({ type, at, ...(code ? { code } : {}) });
  } catch {
    // Audit failures must not expose or alter protected protocol processing.
  }
}

export async function createPseud0WebLoginService<User, Response>(
  options: Pseud0WebLoginServiceOptions<User, Response>,
): Promise<Pseud0WebLoginService<User, Response>> {
  const validated = validateConfig(
    options.config as Pseud0WebLoginServiceOptions<unknown, unknown>["config"],
  );
  const privateKey = await loadAndVerifySiteKey(
    options.config.sitePrivateKey,
    options.config.sitePublicKeyBase64Url,
  );
  const clock = options.clock ?? { now: () => Date.now() };
  const random = options.random ?? nodeRandom;
  const registrationUrl = `${validated.relayOrigin}/v1/site-sessions`;
  const http: RestrictedHttpClient =
    options.http ??
    createRestrictedHttpClient({
      allowedUrls: [registrationUrl, options.config.relayJwksUri],
    });
  const jwks = new RelayJwksCache(options.config.relayJwksUri, http, clock);
  const cfg = options.config;

  const sessionLookup = (session: string) => hmac(cfg.lookupPepper, "session", session);
  const nonceLookup = (nonce: string) => hmac(cfg.lookupPepper, "nonce", nonce);
  const secretHash = (secret: string) => hmac(cfg.lookupPepper, "browser-secret", secret);
  const subjectLookup = (subject: string) => hmac(cfg.lookupPepper, "subject", subject);
  const jtiLookup = (jti: string) => hmac(cfg.lookupPepper, "relay-jti", jti);

  async function findAuthenticated(
    session: string,
    secret: string,
  ): Promise<WebLoginRequestRecord> {
    if (!SESSION.test(session) || !OPAQUE.test(secret)) {
      throw new Pseud0WebLoginError("request_not_found");
    }
    const record = await options.repository.findForUpdate(sessionLookup(session));
    const candidate = secretHash(secret);
    if (!record || !equalBytes(record.browserSecretHash, candidate)) {
      throw new Pseud0WebLoginError("request_not_found");
    }
    if (record.expiresAt < clock.now() && record.state !== "expired") {
      await options.repository.expireBefore(clock.now());
      record.state = "expired";
    }
    return record;
  }

  async function metadata(): Promise<SiteMetadata> {
    const unsigned = {
      displayName: cfg.displayName,
      domain: cfg.domain,
      publicKey: cfg.sitePublicKeyBase64Url,
      version: 1 as const,
    };
    return { ...unsigned, signature: signObject(privateKey, unsigned) };
  }

  return {
    metadata,

    async createBrowserLogin(context): Promise<CreateLoginResult> {
      if (context.origin !== undefined && context.origin !== `https://${cfg.domain}`) {
        throw new Pseud0WebLoginError("invalid_request");
      }
      const session = encodeBase64Url(random.bytes(24));
      const nonce = encodeBase64Url(random.bytes(24));
      const browserSecret = encodeBase64Url(random.bytes(32));
      const iat = clock.now();
      const exp = iat + validated.ttl;
      const qrPayload = buildQrSigningPayload({ domain: cfg.domain, exp, iat, nonce, session });
      const qrSignature = signObject(privateKey, qrPayload);
      const registrationPayload = {
        domain: cfg.domain,
        exp,
        iat,
        nonce,
        qrSignature,
        requestedDisplayName: "",
        sessionId: session,
        version: 1 as const,
      };
      const registrationSignature = signObject(privateKey, registrationPayload);
      const lookup = sessionLookup(session);
      await options.repository.createRegistering({
        sessionLookup: lookup,
        encryptedSession: encrypt(cfg.dataEncryptionKey, "session", session, random),
        browserSecretHash: secretHash(browserSecret),
        nonceLookup: nonceLookup(nonce),
        encryptedNonce: encrypt(cfg.dataEncryptionKey, "nonce", nonce, random),
        state: "registering",
        issuedAt: iat,
        expiresAt: exp,
        version: 0,
      });
      try {
        const body = Buffer.from(
          JSON.stringify({ ...registrationPayload, registrationSignature }),
          "utf8",
        );
        const response = await http.request({
          method: "POST",
          url: registrationUrl,
          headers: { "content-type": "application/json", accept: "application/json" },
          body,
          expectedContentTypes: ["application/json"],
          maxResponseBytes: 16_384,
        });
        if (response.status !== 200 && response.status !== 201) {
          throw new Pseud0WebLoginError("relay_unavailable", response.status >= 500);
        }
        const relayResult = parseStrictJson(response.body);
        assertExactKeys(relayResult, ["version", "sessionId", "status", "expiresAt"]);
        if (
          relayResult.version !== 1 ||
          relayResult.sessionId !== session ||
          relayResult.status !== "registered" ||
          relayResult.expiresAt !== exp
        )
          throw new Pseud0WebLoginError("relay_unavailable");
        if (!(await options.repository.markRegistered(lookup, 0))) {
          throw new Pseud0WebLoginError("internal_error");
        }
        await safeAudit(
          options as Pseud0WebLoginServiceOptions<unknown, unknown>,
          "registration_succeeded",
          clock.now(),
        );
      } catch (error) {
        const code = error instanceof Pseud0WebLoginError ? error.code : "relay_unavailable";
        await safeAudit(
          options as Pseud0WebLoginServiceOptions<unknown, unknown>,
          "registration_failed",
          clock.now(),
          code,
        );
        if (error instanceof Pseud0WebLoginError) throw error;
        throw new Pseud0WebLoginError("relay_unavailable", true);
      }
      const qr = buildQrUri(qrPayload, qrSignature);
      return { session, browser_secret: browserSecret, exp, qr };
    },

    async status(session, browserSecret) {
      const record = await findAuthenticated(session, browserSecret);
      return { session, status: publicStatus(record.state), exp: record.expiresAt };
    },

    async complete(session, browserSecret, response) {
      const lookup = sessionLookup(session);
      const record = await findAuthenticated(session, browserSecret);
      if (record.state === "consumed") throw new Pseud0WebLoginError("request_already_used");
      if (record.state === "expired") throw new Pseud0WebLoginError("request_expired");
      if (record.state === "denied") throw new Pseud0WebLoginError("request_denied");
      if (
        record.state !== "assertion_received" ||
        !record.encryptedSubject ||
        !record.encryptedDisplayName
      ) {
        throw new Pseud0WebLoginError("invalid_request");
      }
      const consumed = await options.repository.consume({
        sessionLookup: lookup,
        expectedVersion: record.version,
      });
      if (consumed === "already_used") throw new Pseud0WebLoginError("request_already_used");
      if (consumed !== "consumed") throw new Pseud0WebLoginError("invalid_request");
      const subject = decrypt(cfg.dataEncryptionKey, "subject", record.encryptedSubject);
      const displayName = decrypt(
        cfg.dataEncryptionKey,
        "display-name",
        record.encryptedDisplayName,
      );
      let user = await options.identities.findByPseud0Subject(subject);
      if (!user) user = await options.identities.createFromPseud0({ subject, displayName });
      await options.identities.onSuccessfulLogin?.(user, { displayName });
      await options.sessions.issueSession(user, response);
      await safeAudit(
        options as Pseud0WebLoginServiceOptions<unknown, unknown>,
        "completion_succeeded",
        clock.now(),
      );
    },

    async cancel(session, browserSecret) {
      const record = await findAuthenticated(session, browserSecret);
      if (["consumed", "denied", "expired", "cancelled"].includes(record.state)) return;
      await options.repository.cancel(sessionLookup(session), record.version);
    },

    async acceptAssertion(rawBody, headers): Promise<RelayCallbackResult> {
      let assertion: RelayAssertion;
      try {
        assertion = parseAssertion(rawBody);
        if (assertion.iss !== ISSUER) throw new Pseud0WebLoginError("invalid_signature");
        if (assertion.aud !== cfg.domain) throw new Pseud0WebLoginError("audience_mismatch");
        if (headers.get("idempotency-key") !== assertion.jti)
          throw new Pseud0WebLoginError("invalid_request");
        validateTimes(assertion, clock.now(), validated.skew);
        await jwks.verify(assertion.kid, assertion.signature, withoutSignature(assertion));
        const record = await options.repository.findForUpdate(sessionLookup(assertion.sessionId));
        if (!record) throw new Pseud0WebLoginError("request_not_found");
        if (record.state !== "registered" && !record.assertionHash) {
          throw new Pseud0WebLoginError("assertion_replayed");
        }
        if (
          assertion.exp > record.expiresAt ||
          !equalBytes(record.nonceLookup, nonceLookup(assertion.nonce))
        )
          throw new Pseud0WebLoginError("invalid_request");
        const result = await options.repository.acceptAssertion({
          sessionLookup: sessionLookup(assertion.sessionId),
          nonceLookup: nonceLookup(assertion.nonce),
          relayJtiLookup: jtiLookup(assertion.jti),
          assertionHash: hashBody(rawBody),
          encryptedSubject: encrypt(cfg.dataEncryptionKey, "subject", assertion.sub, random),
          encryptedDisplayName: encrypt(
            cfg.dataEncryptionKey,
            "display-name",
            assertion.displayName,
            random,
          ),
          expiresAt: assertion.exp + validated.skew,
          now: clock.now(),
        });
        if (result === "replay") throw new Pseud0WebLoginError("assertion_replayed");
        await safeAudit(
          options as Pseud0WebLoginServiceOptions<unknown, unknown>,
          "assertion_accepted",
          clock.now(),
        );
        return {
          sessionId: assertion.sessionId,
          status: result === "accepted" ? "accepted" : "already_accepted",
          receivedAt: clock.now(),
        };
      } catch (error) {
        const code = error instanceof Pseud0WebLoginError ? error.code : "invalid_request";
        await safeAudit(
          options as Pseud0WebLoginServiceOptions<unknown, unknown>,
          "assertion_rejected",
          clock.now(),
          code,
        );
        if (error instanceof Pseud0WebLoginError) throw error;
        throw new Pseud0WebLoginError("invalid_request");
      }
    },

    async acceptRevocation(rawBody, headers): Promise<RelayCallbackResult> {
      const revocation = parseRevocation(rawBody);
      if (revocation.iss !== ISSUER) throw new Pseud0WebLoginError("invalid_signature");
      if (revocation.aud !== cfg.domain) throw new Pseud0WebLoginError("audience_mismatch");
      if (headers.get("idempotency-key") !== revocation.jti)
        throw new Pseud0WebLoginError("invalid_request");
      validateTimes(revocation, clock.now(), validated.skew);
      await jwks.verify(revocation.kid, revocation.signature, withoutSignature(revocation));
      if (!options.repository.acceptRevocation) throw new Pseud0WebLoginError("internal_error");
      const result = await options.repository.acceptRevocation({
        relayJtiLookup: jtiLookup(revocation.jti),
        subjectLookup: subjectLookup(revocation.sub),
        payloadHash: hashBody(rawBody),
        retainUntil: revocation.exp + validated.skew,
      });
      if (result === "replay") throw new Pseud0WebLoginError("assertion_replayed");
      if (result === "accepted") {
        const user = await options.identities.findByPseud0Subject(revocation.sub);
        if (user) {
          await options.identities.onRevocation?.(user, revocation.reason || undefined);
          await options.sessions.revokeSessions?.(user);
        }
      }
      await safeAudit(
        options as Pseud0WebLoginServiceOptions<unknown, unknown>,
        "revocation_accepted",
        clock.now(),
      );
      return {
        status: result === "accepted" ? "accepted" : "already_accepted",
        receivedAt: clock.now(),
      };
    },
  };
}
