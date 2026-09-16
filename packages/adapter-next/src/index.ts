import {
  Pseud0WebLoginError,
  type Pseud0WebLoginErrorCode,
  type Pseud0WebLoginService,
  type RelayCallbackResult,
} from "@pseud0/web-login-node";

export const runtime = "nodejs";
export const MAX_CALLBACK_BODY_BYTES = 16 * 1024;

export const PSEUD0_WEB_LOGIN_PATHS = Object.freeze({
  metadata: "/.well-known/pseud0-web-login",
  sessions: "/pseud0/web-login/sessions",
  status: "/pseud0/web-login/sessions/[session]/status",
  complete: "/pseud0/web-login/sessions/[session]/complete",
  cancel: "/pseud0/web-login/sessions/[session]/cancel",
  assertions: "/pseud0/web-login/assertions",
  revocations: "/pseud0/web-login/revocations",
} as const);

const JSON_CONTENT_TYPE = "application/json";
const PROBLEM_CONTENT_TYPE = "application/problem+json";
const SESSION_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const SECRET_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;

export interface Pseud0NextRouteContext {
  params: { session?: string } | Promise<{ session?: string }>;
}

export interface Pseud0NextAdapterOptions {
  /**
   * Require Sec-Fetch-Site: same-origin on browser POST routes.
   * Keep enabled unless an upstream known to be trusted strips Fetch Metadata.
   */
  requireFetchMetadata?: boolean;
}

export type Pseud0NextStaticHandler = (request: Request) => Promise<Response>;
export type Pseud0NextSessionHandler = (
  request: Request,
  context: Pseud0NextRouteContext,
) => Promise<Response>;

export interface Pseud0NextRouteHandlers {
  metadata: { GET: Pseud0NextStaticHandler };
  sessions: { POST: Pseud0NextStaticHandler };
  status: { POST: Pseud0NextSessionHandler };
  complete: { POST: Pseud0NextSessionHandler };
  cancel: { POST: Pseud0NextSessionHandler };
  assertions: { POST: Pseud0NextStaticHandler };
  revocations: { POST: Pseud0NextStaticHandler };
}

interface ProblemDescription {
  status: number;
  title: string;
}

const PROBLEMS: Readonly<Record<Pseud0WebLoginErrorCode, ProblemDescription>> = {
  invalid_request: { status: 400, title: "Invalid request" },
  invalid_signature: { status: 401, title: "Invalid signature" },
  domain_verification_failed: { status: 403, title: "Domain verification failed" },
  request_not_found: { status: 404, title: "Request not found" },
  request_expired: { status: 410, title: "Request expired" },
  request_denied: { status: 409, title: "Request denied" },
  request_already_used: { status: 409, title: "Request already used" },
  assertion_replayed: { status: 409, title: "Assertion replayed" },
  audience_mismatch: { status: 403, title: "Audience mismatch" },
  rate_limited: { status: 429, title: "Rate limited" },
  relay_unavailable: { status: 503, title: "Relay unavailable" },
  internal_error: { status: 500, title: "Internal error" },
};

function responseHeaders(contentType: string, cacheControl = "no-store"): Headers {
  return new Headers({
    "cache-control": cacheControl,
    "content-type": contentType,
    "x-content-type-options": "nosniff",
  });
}

function json(value: unknown, status: number, cacheControl = "no-store"): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: responseHeaders(JSON_CONTENT_TYPE, cacheControl),
  });
}

function empty(status: number): Response {
  return new Response(null, {
    status,
    headers: new Headers({
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    }),
  });
}

function problem(error: unknown): Response {
  const sdkError =
    error instanceof Pseud0WebLoginError ? error : new Pseud0WebLoginError("internal_error");
  const description = PROBLEMS[sdkError.code];
  return new Response(
    JSON.stringify({
      type: `https://pseud0.org/problems/${sdkError.code}`,
      title: description.title,
      status: description.status,
      code: sdkError.code,
      retryable: sdkError.retryable,
    }),
    {
      status: description.status,
      headers: responseHeaders(PROBLEM_CONTENT_TYPE),
    },
  );
}

function hasJsonContentType(request: Request): boolean {
  return (
    request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() ===
    JSON_CONTENT_TYPE
  );
}

async function readLimitedBody(request: Request, limit: number): Promise<Uint8Array> {
  const declaredLength = request.headers.get("content-length");
  if (declaredLength !== null) {
    const parsed = Number(declaredLength);
    if (!Number.isSafeInteger(parsed) || parsed < 0 || parsed > limit) {
      throw new Pseud0WebLoginError("invalid_request");
    }
  }

  if (request.body === null) return new Uint8Array();
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.byteLength;
      if (length > limit) {
        await reader.cancel();
        throw new Pseud0WebLoginError("invalid_request");
      }
      chunks.push(value);
    }
  } catch (error) {
    if (error instanceof Pseud0WebLoginError) throw error;
    throw new Pseud0WebLoginError("invalid_request");
  } finally {
    reader.releaseLock();
  }

  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

function parseBrowserSecret(bytes: Uint8Array): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Pseud0WebLoginError("invalid_request");
  }

  // The only accepted shape is the OpenAPI BrowserSecret object. This also
  // rejects duplicate/unknown fields before any value reaches the service.
  const match = /^\s*\{\s*"browser_secret"\s*:\s*"([A-Za-z0-9_-]{22,128})"\s*\}\s*$/.exec(text);
  if (!match?.[1] || !SECRET_PATTERN.test(match[1])) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  return match[1];
}

function assertBrowserRequest(request: Request, requireFetchMetadata: boolean): string {
  const requestOrigin = new URL(request.url).origin;
  if (request.headers.get("origin") !== requestOrigin) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  if (requireFetchMetadata && request.headers.get("sec-fetch-site") !== "same-origin") {
    throw new Pseud0WebLoginError("invalid_request");
  }
  return requestOrigin;
}

async function browserSecret(request: Request): Promise<string> {
  if (!hasJsonContentType(request)) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  return parseBrowserSecret(await readLimitedBody(request, MAX_CALLBACK_BODY_BYTES));
}

async function sessionFrom(context: Pseud0NextRouteContext): Promise<string> {
  const session = (await context.params).session;
  if (typeof session !== "string" || !SESSION_PATTERN.test(session)) {
    throw new Pseud0WebLoginError("request_not_found");
  }
  return session;
}

function callbackStatus(result: RelayCallbackResult): number {
  return result.status === "accepted" ? 202 : 200;
}

/**
 * Builds handlers for the seven canonical Next.js App Router route files.
 * Route modules must also export `const runtime = "nodejs"` so Next can
 * statically select the Node runtime.
 */
export function createPseud0WebLoginRouteHandlers<User>(
  service: Pseud0WebLoginService<User, Response>,
  options: Pseud0NextAdapterOptions = {},
): Pseud0NextRouteHandlers {
  const requireFetchMetadata = options.requireFetchMetadata ?? true;

  return {
    metadata: {
      async GET() {
        try {
          return json(await service.metadata(), 200, "public, max-age=300");
        } catch (error) {
          return problem(error);
        }
      },
    },
    sessions: {
      async POST(request) {
        try {
          const origin = assertBrowserRequest(request, requireFetchMetadata);
          return json(await service.createBrowserLogin({ origin }), 201);
        } catch (error) {
          return problem(error);
        }
      },
    },
    status: {
      async POST(request, context) {
        try {
          assertBrowserRequest(request, requireFetchMetadata);
          return json(
            await service.status(await sessionFrom(context), await browserSecret(request)),
            200,
          );
        } catch (error) {
          return problem(error);
        }
      },
    },
    complete: {
      async POST(request, context) {
        try {
          assertBrowserRequest(request, requireFetchMetadata);
          const response = empty(204);
          await service.complete(
            await sessionFrom(context),
            await browserSecret(request),
            response,
          );
          return response;
        } catch (error) {
          return problem(error);
        }
      },
    },
    cancel: {
      async POST(request, context) {
        try {
          assertBrowserRequest(request, requireFetchMetadata);
          await service.cancel(await sessionFrom(context), await browserSecret(request));
          return empty(204);
        } catch (error) {
          return problem(error);
        }
      },
    },
    assertions: {
      async POST(request) {
        try {
          if (!hasJsonContentType(request)) {
            throw new Pseud0WebLoginError("invalid_request");
          }
          const result = await service.acceptAssertion(
            await readLimitedBody(request, MAX_CALLBACK_BODY_BYTES),
            request.headers,
          );
          return json(result, callbackStatus(result));
        } catch (error) {
          return problem(error);
        }
      },
    },
    revocations: {
      async POST(request) {
        try {
          if (!hasJsonContentType(request)) {
            throw new Pseud0WebLoginError("invalid_request");
          }
          const result = await service.acceptRevocation(
            await readLimitedBody(request, MAX_CALLBACK_BODY_BYTES),
            request.headers,
          );
          return json(result, callbackStatus(result));
        } catch (error) {
          return problem(error);
        }
      },
    },
  };
}
