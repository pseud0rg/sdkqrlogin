import type { KeyObject } from "node:crypto";

export type LoginState =
  | "registering"
  | "registered"
  | "assertion_received"
  | "consumed"
  | "denied"
  | "expired"
  | "cancelled";

export interface WebLoginRequestRecord {
  sessionLookup: Uint8Array;
  encryptedSession: Uint8Array;
  browserSecretHash: Uint8Array;
  nonceLookup: Uint8Array;
  encryptedNonce: Uint8Array;
  state: LoginState;
  issuedAt: number;
  expiresAt: number;
  encryptedSubject?: Uint8Array;
  encryptedDisplayName?: Uint8Array;
  relayJtiLookup?: Uint8Array;
  assertionHash?: Uint8Array;
  version: number;
}

export interface AcceptAssertionTransaction {
  sessionLookup: Uint8Array;
  nonceLookup: Uint8Array;
  relayJtiLookup: Uint8Array;
  assertionHash: Uint8Array;
  encryptedSubject: Uint8Array;
  encryptedDisplayName: Uint8Array;
  expiresAt: number;
  now: number;
}

export interface ConsumeTransaction {
  sessionLookup: Uint8Array;
  expectedVersion: number;
}

export interface AcceptRevocationTransaction {
  relayJtiLookup: Uint8Array;
  subjectLookup: Uint8Array;
  payloadHash: Uint8Array;
  retainUntil: number;
}

export interface WebLoginRepository {
  createRegistering(record: WebLoginRequestRecord): Promise<void>;
  markRegistered(sessionLookup: Uint8Array, expectedVersion: number): Promise<boolean>;
  findForUpdate(sessionLookup: Uint8Array): Promise<WebLoginRequestRecord | null>;
  acceptAssertion(input: AcceptAssertionTransaction): Promise<"accepted" | "same_retry" | "replay">;
  consume(input: ConsumeTransaction): Promise<"consumed" | "already_used" | "invalid_state">;
  cancel(sessionLookup: Uint8Array, expectedVersion: number): Promise<boolean>;
  acceptRevocation?(
    input: AcceptRevocationTransaction,
  ): Promise<"accepted" | "same_retry" | "replay">;
  expireBefore(now: number): Promise<number>;
}

export interface IdentityAdapter<User> {
  findByPseud0Subject(subject: string): Promise<User | null>;
  createFromPseud0(input: { subject: string; displayName: string }): Promise<User>;
  onSuccessfulLogin?(user: User, profile: { displayName: string }): Promise<void>;
  onRevocation?(user: User, reason?: string): Promise<void>;
}

export interface SessionAdapter<User, Response> {
  issueSession(user: User, response: Response): Promise<void>;
  revokeSessions?(user: User): Promise<void>;
}

export type SitePrivateKey =
  KeyObject | CryptoKey | (() => KeyObject | CryptoKey | Promise<KeyObject | CryptoKey>);

export interface Pseud0WebLoginConfig {
  enabled: boolean;
  domain: string;
  displayName: string;
  relayOrigin: string;
  relayJwksUri: string;
  sitePrivateKey: SitePrivateKey;
  sitePublicKeyBase64Url: string;
  requestTtlMs?: number;
  allowedClockSkewMs?: number;
  lookupPepper: Uint8Array;
  dataEncryptionKey: Uint8Array;
}

export interface RestrictedHttpRequest {
  method: "GET" | "POST";
  url: string;
  headers?: Readonly<Record<string, string>>;
  body?: Uint8Array;
  idempotencyKey?: string;
  expectedContentTypes: readonly string[];
  maxResponseBytes: number;
  timeoutMs?: number;
}

export interface RestrictedHttpResponse {
  status: number;
  headers: Readonly<Record<string, string | undefined>>;
  body: Uint8Array;
}

export interface RestrictedHttpClient {
  request(request: RestrictedHttpRequest): Promise<RestrictedHttpResponse>;
}

export interface Clock {
  now(): number;
}

export interface SecureRandom {
  bytes(length: number): Uint8Array;
}

export interface RedactedAuditSink {
  record(event: {
    type:
      | "registration_succeeded"
      | "registration_failed"
      | "assertion_accepted"
      | "assertion_rejected"
      | "revocation_accepted"
      | "completion_succeeded";
    at: number;
    code?: Pseud0WebLoginErrorCode;
  }): void | Promise<void>;
}

export interface BrowserRequestContext {
  origin?: string;
}

export interface SiteMetadata {
  version: 1;
  domain: string;
  displayName: string;
  publicKey: string;
  signature: string;
}

export interface CreateLoginResult {
  session: string;
  browser_secret: string;
  exp: number;
  qr: string;
}

export interface PublicLoginStatus {
  session: string;
  status: "pending" | "ready" | "denied" | "expired" | "cancelled" | "consumed";
  exp: number;
}

export interface HeadersLike {
  get(name: string): string | null;
}

export interface RelayCallbackResult {
  sessionId?: string;
  status: "accepted" | "already_accepted";
  receivedAt: number;
}

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

export class Pseud0WebLoginError extends Error {
  public constructor(
    public readonly code: Pseud0WebLoginErrorCode,
    public readonly retryable = false,
  ) {
    super(code);
    this.name = "Pseud0WebLoginError";
  }
}

export interface Pseud0WebLoginServiceOptions<User, Response> {
  config: Pseud0WebLoginConfig;
  repository: WebLoginRepository;
  identities: IdentityAdapter<User>;
  sessions: SessionAdapter<User, Response>;
  http?: RestrictedHttpClient;
  clock?: Clock;
  random?: SecureRandom;
  audit?: RedactedAuditSink;
}

export interface Pseud0WebLoginService<User, Response> {
  metadata(): Promise<SiteMetadata>;
  createBrowserLogin(context: BrowserRequestContext): Promise<CreateLoginResult>;
  status(session: string, browserSecret: string): Promise<PublicLoginStatus>;
  complete(session: string, browserSecret: string, response: Response): Promise<void>;
  cancel(session: string, browserSecret: string): Promise<void>;
  acceptAssertion(rawBody: Uint8Array, headers: HeadersLike): Promise<RelayCallbackResult>;
  acceptRevocation(rawBody: Uint8Array, headers: HeadersLike): Promise<RelayCallbackResult>;
}
