import { Pseud0WebLoginError } from "@pseud0/web-login-node";
import type {
  HeadersLike,
  Pseud0WebLoginErrorCode,
  Pseud0WebLoginService,
} from "@pseud0/web-login-node";
import type { FastifyError, FastifyPluginAsync, FastifyReply, FastifyRequest } from "fastify";

export const WEB_LOGIN_BODY_LIMIT = 16 * 1024;

export const WEB_LOGIN_PATHS = {
  metadata: "/.well-known/pseud0-web-login",
  sessions: "/pseud0/web-login/sessions",
  status: "/pseud0/web-login/sessions/:session/status",
  complete: "/pseud0/web-login/sessions/:session/complete",
  cancel: "/pseud0/web-login/sessions/:session/cancel",
  assertions: "/pseud0/web-login/assertions",
  revocations: "/pseud0/web-login/revocations",
} as const;

const SESSION_PATTERN = "^[A-Za-z0-9_-]{16,128}$";
const OPAQUE_PATTERN = "^[A-Za-z0-9_-]{22,128}$";
const JSON_CONTENT_TYPE = /^application\/json(?:\s*;\s*charset=utf-8)?$/i;

const sessionParamsSchema = {
  type: "object",
  additionalProperties: false,
  required: ["session"],
  properties: {
    session: { type: "string", pattern: SESSION_PATTERN },
  },
} as const;

const browserSecretSchema = {
  type: "object",
  additionalProperties: false,
  required: ["browser_secret"],
  properties: {
    browser_secret: { type: "string", pattern: OPAQUE_PATTERN },
  },
} as const;

const callbackHeadersSchema = {
  type: "object",
  required: ["idempotency-key"],
  properties: {
    "idempotency-key": { type: "string", pattern: OPAQUE_PATTERN },
  },
} as const;

export const webLoginFastifySchemas = {
  sessionParams: sessionParamsSchema,
  browserSecret: browserSecretSchema,
  callbackHeaders: callbackHeadersSchema,
} as const;

export interface Pseud0WebLoginFastifyOptions {
  /**
   * A fully trusted, configured website origin. It is never inferred from Host
   * or forwarded headers.
   */
  browserOrigin: string;
  /**
   * The application-owned service. In particular, the adapter creates neither
   * cryptographic material nor an application session implementation.
   */
  service: Pseud0WebLoginService<unknown, FastifyReply>;
}

interface SessionParams {
  session: string;
}

interface BrowserSecretBody {
  browser_secret: string;
}

interface StatusCodeError extends Error {
  statusCode?: number;
  validation?: unknown;
}

interface Problem {
  type: string;
  title: string;
  status: number;
  code: Pseud0WebLoginErrorCode;
  retryable: boolean;
}

const ERROR_STATUS: Readonly<Record<Pseud0WebLoginErrorCode, number>> = {
  invalid_request: 400,
  invalid_signature: 401,
  domain_verification_failed: 403,
  request_not_found: 404,
  request_expired: 410,
  request_denied: 409,
  request_already_used: 409,
  assertion_replayed: 409,
  audience_mismatch: 403,
  rate_limited: 429,
  relay_unavailable: 503,
  internal_error: 500,
};

const ERROR_TITLE: Readonly<Record<Pseud0WebLoginErrorCode, string>> = {
  invalid_request: "Invalid request",
  invalid_signature: "Invalid signature",
  domain_verification_failed: "Domain verification failed",
  request_not_found: "Request not found",
  request_expired: "Request expired",
  request_denied: "Request denied",
  request_already_used: "Request already used",
  assertion_replayed: "Assertion replayed",
  audience_mismatch: "Audience mismatch",
  rate_limited: "Rate limited",
  relay_unavailable: "Relay unavailable",
  internal_error: "Internal error",
};

function configuredOrigin(value: string): string {
  try {
    const url = new URL(value);
    if (
      url.protocol !== "https:" ||
      url.username ||
      url.password ||
      url.pathname !== "/" ||
      url.search ||
      url.hash ||
      url.origin !== value
    ) {
      throw new Error("non-canonical origin");
    }
    return url.origin;
  } catch {
    throw new Error("browserOrigin must be a canonical HTTPS origin");
  }
}

function topLevelPropertyCount(json: string): number {
  let depth = 0;
  let count = 0;
  let inString = false;
  let escaped = false;
  for (const character of json) {
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === "{" || character === "[") depth += 1;
    else if (character === "}" || character === "]") depth -= 1;
    else if (character === ":" && depth === 1) count += 1;
  }
  return count;
}

function parseJsonBody(body: Buffer, route: string | undefined): unknown {
  const text = body.toString("utf8");
  const parsed = JSON.parse(text) as unknown;
  if (
    route === WEB_LOGIN_PATHS.status ||
    route === WEB_LOGIN_PATHS.complete ||
    route === WEB_LOGIN_PATHS.cancel
  ) {
    if (
      typeof parsed !== "object" ||
      parsed === null ||
      Array.isArray(parsed) ||
      topLevelPropertyCount(text) !== 1 ||
      Object.keys(parsed).length !== 1 ||
      !Object.hasOwn(parsed, "browser_secret")
    ) {
      throw new Pseud0WebLoginError("invalid_request");
    }
  }
  return parsed;
}

function headerOccurrences(request: FastifyRequest, name: string): number {
  let count = 0;
  for (let index = 0; index < request.raw.rawHeaders.length; index += 2) {
    if (request.raw.rawHeaders[index]?.toLowerCase() === name) count += 1;
  }
  return count;
}

function singleHeader(request: FastifyRequest, name: string): string | undefined {
  if (headerOccurrences(request, name) !== 1) return undefined;
  const value = request.headers[name];
  return typeof value === "string" ? value : undefined;
}

function requireJsonContentType(request: FastifyRequest): void {
  const contentType = singleHeader(request, "content-type");
  if (!contentType || !JSON_CONTENT_TYPE.test(contentType)) {
    throw new Pseud0WebLoginError("invalid_request");
  }
}

function requireBrowserRequest(request: FastifyRequest, origin: string): void {
  if (singleHeader(request, "origin") !== origin) {
    throw new Pseud0WebLoginError("invalid_request");
  }

  const fetchSiteCount = headerOccurrences(request, "sec-fetch-site");
  if (fetchSiteCount > 1) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  if (fetchSiteCount === 1 && singleHeader(request, "sec-fetch-site") !== "same-origin") {
    throw new Pseud0WebLoginError("invalid_request");
  }
}

function requireCallbackRequest(request: FastifyRequest): void {
  requireJsonContentType(request);
  if (!singleHeader(request, "idempotency-key")) {
    throw new Pseud0WebLoginError("invalid_request");
  }
}

function serviceHeaders(request: FastifyRequest): HeadersLike {
  return {
    get(name): string | null {
      return singleHeader(request, name.toLowerCase()) ?? null;
    },
  };
}

function problemFor(error: unknown): Problem {
  if (error instanceof Pseud0WebLoginError) {
    const status = ERROR_STATUS[error.code];
    return {
      type: `https://pseud0.org/problems/${error.code}`,
      title: ERROR_TITLE[error.code],
      status,
      code: error.code,
      retryable: error.retryable,
    };
  }

  const fastifyError = error as StatusCodeError;
  const status =
    fastifyError.statusCode === 413
      ? 413
      : fastifyError.validation || (fastifyError.statusCode ?? 0) < 500
        ? 400
        : 500;
  const code: Pseud0WebLoginErrorCode = status === 500 ? "internal_error" : "invalid_request";
  return {
    type: `https://pseud0.org/problems/${code}`,
    title: ERROR_TITLE[code],
    status,
    code,
    retryable: false,
  };
}

function noStore(reply: FastifyReply): FastifyReply {
  return reply.header("cache-control", "no-store").header("x-content-type-options", "nosniff");
}

/**
 * Encapsulated Fastify plugin. Registering it creates a child scope: its raw
 * JSON parser and error handler do not alter the parent Fastify application.
 */
export const pseud0WebLoginFastify: FastifyPluginAsync<Pseud0WebLoginFastifyOptions> = async (
  fastify,
  options,
) => {
  const browserOrigin = configuredOrigin(options.browserOrigin);
  const service = options.service;

  fastify.removeContentTypeParser("application/json");
  fastify.addContentTypeParser(
    "application/json",
    { parseAs: "buffer", bodyLimit: WEB_LOGIN_BODY_LIMIT },
    (request, body, done) => {
      const route = request.routeOptions.url;
      if (route === WEB_LOGIN_PATHS.assertions || route === WEB_LOGIN_PATHS.revocations) {
        done(null, body);
        return;
      }
      try {
        if (!Buffer.isBuffer(body)) {
          throw new Pseud0WebLoginError("invalid_request");
        }
        done(null, parseJsonBody(body, route));
      } catch (error) {
        done(error as Error);
      }
    },
  );

  fastify.setErrorHandler((error: FastifyError, _request, reply) => {
    if (reply.sent) return;
    const problem = problemFor(error);
    noStore(reply).code(problem.status).type("application/problem+json").send(problem);
  });

  fastify.get(WEB_LOGIN_PATHS.metadata, async (_request, reply) => {
    const metadata = await service.metadata();
    return reply
      .header("cache-control", "public, max-age=300")
      .header("x-content-type-options", "nosniff")
      .type("application/json")
      .send(metadata);
  });

  fastify.post(WEB_LOGIN_PATHS.sessions, async (request, reply) => {
    requireBrowserRequest(request, browserOrigin);
    if (request.body !== undefined) {
      throw new Pseud0WebLoginError("invalid_request");
    }
    const result = await service.createBrowserLogin({ origin: browserOrigin });
    return noStore(reply).code(201).type("application/json").send(result);
  });

  fastify.post<{
    Params: SessionParams;
    Body: BrowserSecretBody;
  }>(
    WEB_LOGIN_PATHS.status,
    { schema: { params: sessionParamsSchema, body: browserSecretSchema } },
    async (request, reply) => {
      requireBrowserRequest(request, browserOrigin);
      requireJsonContentType(request);
      const result = await service.status(request.params.session, request.body.browser_secret);
      return noStore(reply).type("application/json").send(result);
    },
  );

  fastify.post<{
    Params: SessionParams;
    Body: BrowserSecretBody;
  }>(
    WEB_LOGIN_PATHS.complete,
    { schema: { params: sessionParamsSchema, body: browserSecretSchema } },
    async (request, reply) => {
      requireBrowserRequest(request, browserOrigin);
      requireJsonContentType(request);
      noStore(reply);
      await service.complete(request.params.session, request.body.browser_secret, reply);
      return reply.code(204).send();
    },
  );

  fastify.post<{
    Params: SessionParams;
    Body: BrowserSecretBody;
  }>(
    WEB_LOGIN_PATHS.cancel,
    { schema: { params: sessionParamsSchema, body: browserSecretSchema } },
    async (request, reply) => {
      requireBrowserRequest(request, browserOrigin);
      requireJsonContentType(request);
      await service.cancel(request.params.session, request.body.browser_secret);
      return noStore(reply).code(204).send();
    },
  );

  fastify.post(
    WEB_LOGIN_PATHS.assertions,
    {
      schema: { headers: callbackHeadersSchema },
      bodyLimit: WEB_LOGIN_BODY_LIMIT,
    },
    async (request, reply) => {
      requireCallbackRequest(request);
      if (!Buffer.isBuffer(request.body)) {
        throw new Pseud0WebLoginError("invalid_request");
      }
      const result = await service.acceptAssertion(request.body, serviceHeaders(request));
      const status = result.status === "accepted" ? 202 : 200;
      return noStore(reply).code(status).type("application/json").send(result);
    },
  );

  fastify.post(
    WEB_LOGIN_PATHS.revocations,
    {
      schema: { headers: callbackHeadersSchema },
      bodyLimit: WEB_LOGIN_BODY_LIMIT,
    },
    async (request, reply) => {
      requireCallbackRequest(request);
      if (!Buffer.isBuffer(request.body)) {
        throw new Pseud0WebLoginError("invalid_request");
      }
      const result = await service.acceptRevocation(request.body, serviceHeaders(request));
      const status = result.status === "accepted" ? 202 : 200;
      return noStore(reply).code(status).type("application/json").send(result);
    },
  );
};

export default pseud0WebLoginFastify;
