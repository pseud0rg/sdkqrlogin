import {
  Pseud0WebLoginError,
  type Pseud0WebLoginErrorCode,
  type Pseud0WebLoginService,
} from "@pseud0/web-login-node";
import express, {
  type ErrorRequestHandler,
  type Request,
  type RequestHandler,
  type Response,
  type Router,
} from "express";
import { parseBrowserSecret } from "./strict-json.js";

export const PSEUD0_WEB_LOGIN_MAX_BODY_BYTES = 16_384;

export interface BrowserRequestValidationContext {
  request: Request;
  expectedOrigin: string;
}

export type BrowserRequestValidator = (
  context: BrowserRequestValidationContext,
) => boolean | Promise<boolean>;

export interface Pseud0WebLoginExpressOptions<User> {
  service: Pseud0WebLoginService<User, Response>;
  /** Canonical lower-case DNS name, without a scheme or port. */
  domain: string;
  /**
   * Replaces the default Origin and Fetch Metadata policy. The callback must
   * make its decision only from trusted Express request properties/headers.
   */
  validateBrowserRequest?: BrowserRequestValidator;
}

export interface Pseud0WebLoginExpressHandlers {
  rawBody: RequestHandler;
  metadata: RequestHandler;
  createSession: RequestHandler;
  status: RequestHandler;
  complete: RequestHandler;
  cancel: RequestHandler;
  assertion: RequestHandler;
  revocation: RequestHandler;
  error: ErrorRequestHandler;
}

interface Problem {
  type: string;
  title: string;
  status: number;
  code: Pseud0WebLoginErrorCode;
  retryable: boolean;
}

const DOMAIN = /^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

const ERROR_DETAILS: Readonly<Record<Pseud0WebLoginErrorCode, { status: number; title: string }>> =
  {
    invalid_request: { status: 400, title: "Invalid request" },
    invalid_signature: { status: 401, title: "Invalid signature" },
    domain_verification_failed: { status: 403, title: "Domain verification failed" },
    request_not_found: { status: 404, title: "Request not found" },
    request_expired: { status: 409, title: "Request expired" },
    request_denied: { status: 409, title: "Request denied" },
    request_already_used: { status: 409, title: "Request already used" },
    assertion_replayed: { status: 409, title: "Assertion replayed" },
    audience_mismatch: { status: 403, title: "Audience mismatch" },
    rate_limited: { status: 429, title: "Rate limited" },
    relay_unavailable: { status: 503, title: "Relay unavailable" },
    internal_error: { status: 500, title: "Internal error" },
  };

function asyncHandler(
  handler: (request: Request, response: Response) => Promise<void>,
): RequestHandler {
  return (request, response, next) => {
    void handler(request, response).catch(next);
  };
}

function securityHeaders(response: Response): void {
  response.set({
    "X-Content-Type-Options": "nosniff",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
  });
}

function body(request: Request): Buffer {
  if (!Buffer.isBuffer(request.body)) {
    throw new Pseud0WebLoginError("invalid_request");
  }
  return request.body;
}

function requireJson(request: Request): void {
  if (!request.is("application/json")) {
    throw new Pseud0WebLoginError("invalid_request");
  }
}

function requestHeaders(request: Request): { get(name: string): string | null } {
  return {
    get(name) {
      const value = request.get(name);
      return value === undefined ? null : value;
    },
  };
}

function sessionParameter(request: Request): string {
  const session = request.params.session;
  return typeof session === "string" ? session : "";
}

function defaultBrowserRequestIsValid(request: Request, expectedOrigin: string): boolean {
  if (request.get("origin") !== expectedOrigin) return false;
  const site = request.get("sec-fetch-site");
  if (site !== undefined && site !== "same-origin") return false;
  const mode = request.get("sec-fetch-mode");
  if (mode !== undefined && mode !== "cors" && mode !== "same-origin") return false;
  const destination = request.get("sec-fetch-dest");
  return destination === undefined || destination === "empty";
}

function toProblem(error: unknown): Problem {
  const sdkError =
    error instanceof Pseud0WebLoginError ? error : new Pseud0WebLoginError("internal_error");
  const detail = ERROR_DETAILS[sdkError.code];
  return {
    type: `https://pseud0.org/problems/${sdkError.code}`,
    title: detail.title,
    status: detail.status,
    code: sdkError.code,
    retryable: sdkError.retryable,
  };
}

export function createPseud0WebLoginHandlers<User>(
  options: Pseud0WebLoginExpressOptions<User>,
): Pseud0WebLoginExpressHandlers {
  if (!DOMAIN.test(options.domain)) {
    throw new TypeError("domain must be a canonical lower-case DNS name");
  }
  const expectedOrigin = `https://${options.domain}`;
  const validateBrowserRequest =
    options.validateBrowserRequest ??
    (({ request }: BrowserRequestValidationContext) =>
      defaultBrowserRequestIsValid(request, expectedOrigin));

  async function authorizeBrowser(request: Request): Promise<void> {
    if (!(await validateBrowserRequest({ request, expectedOrigin }))) {
      throw new Pseud0WebLoginError("invalid_request");
    }
  }

  const rawBody = express.raw({
    type: () => true,
    limit: PSEUD0_WEB_LOGIN_MAX_BODY_BYTES,
  });

  return {
    rawBody,

    metadata: asyncHandler(async (_request, response) => {
      securityHeaders(response);
      response.set("Cache-Control", "public, max-age=300");
      response
        .status(200)
        .type("application/json")
        .send(await options.service.metadata());
    }),

    createSession: asyncHandler(async (request, response) => {
      securityHeaders(response);
      response.set("Cache-Control", "no-store");
      await authorizeBrowser(request);
      if (
        request.body !== undefined &&
        (!Buffer.isBuffer(request.body) || request.body.byteLength !== 0)
      ) {
        throw new Pseud0WebLoginError("invalid_request");
      }
      const result = await options.service.createBrowserLogin({ origin: expectedOrigin });
      response.status(201).type("application/json").send(result);
    }),

    status: asyncHandler(async (request, response) => {
      securityHeaders(response);
      response.set("Cache-Control", "no-store");
      await authorizeBrowser(request);
      requireJson(request);
      const secret = parseBrowserSecret(body(request));
      const result = await options.service.status(sessionParameter(request), secret);
      response.status(200).type("application/json").send(result);
    }),

    complete: asyncHandler(async (request, response) => {
      securityHeaders(response);
      response.set("Cache-Control", "no-store");
      await authorizeBrowser(request);
      requireJson(request);
      const secret = parseBrowserSecret(body(request));
      await options.service.complete(sessionParameter(request), secret, response);
      response.status(204).end();
    }),

    cancel: asyncHandler(async (request, response) => {
      securityHeaders(response);
      response.set("Cache-Control", "no-store");
      await authorizeBrowser(request);
      requireJson(request);
      const secret = parseBrowserSecret(body(request));
      await options.service.cancel(sessionParameter(request), secret);
      response.status(204).end();
    }),

    assertion: asyncHandler(async (request, response) => {
      securityHeaders(response);
      response.set("Cache-Control", "no-store");
      requireJson(request);
      const result = await options.service.acceptAssertion(body(request), requestHeaders(request));
      response
        .status(result.status === "already_accepted" ? 200 : 202)
        .type("application/json")
        .send(result);
    }),

    revocation: asyncHandler(async (request, response) => {
      securityHeaders(response);
      response.set("Cache-Control", "no-store");
      requireJson(request);
      const result = await options.service.acceptRevocation(body(request), requestHeaders(request));
      response
        .status(result.status === "already_accepted" ? 200 : 202)
        .type("application/json")
        .send(result);
    }),

    error: (error, _request, response, _next) => {
      if (response.headersSent) return;
      securityHeaders(response);
      response.set("Cache-Control", "no-store");
      const normalized =
        typeof error === "object" &&
        error !== null &&
        "type" in error &&
        error.type === "entity.too.large"
          ? new Pseud0WebLoginError("invalid_request")
          : error;
      const problem = toProblem(normalized);
      response.status(problem.status).type("application/problem+json").send(problem);
    },
  };
}

export function createPseud0WebLoginRouter<User>(
  options: Pseud0WebLoginExpressOptions<User>,
): Router {
  const handlers = createPseud0WebLoginHandlers(options);
  const router = express.Router();

  router.get("/.well-known/pseud0-web-login", handlers.metadata);
  router.post("/pseud0/web-login/sessions", handlers.rawBody, handlers.createSession);
  router.post("/pseud0/web-login/sessions/:session/status", handlers.rawBody, handlers.status);
  router.post("/pseud0/web-login/sessions/:session/complete", handlers.rawBody, handlers.complete);
  router.post("/pseud0/web-login/sessions/:session/cancel", handlers.rawBody, handlers.cancel);
  router.post("/pseud0/web-login/assertions", handlers.rawBody, handlers.assertion);
  router.post("/pseud0/web-login/revocations", handlers.rawBody, handlers.revocation);
  router.use(handlers.error);

  return router;
}
