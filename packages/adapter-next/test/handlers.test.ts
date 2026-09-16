import { Pseud0WebLoginError, type Pseud0WebLoginService } from "@pseud0/web-login-node";
import { beforeEach, describe, expect, it, vi } from "vitest";
import {
  MAX_CALLBACK_BODY_BYTES,
  PSEUD0_WEB_LOGIN_PATHS,
  createPseud0WebLoginRouteHandlers,
  runtime,
} from "../src/index.js";

const ORIGIN = "https://login.example.org";
const SESSION = "s".repeat(22);
const SECRET = "b".repeat(22);

function browserRequest(path: string, body?: string, headers?: HeadersInit): Request {
  return new Request(`${ORIGIN}${path}`, {
    method: "POST",
    headers: {
      origin: ORIGIN,
      "sec-fetch-site": "same-origin",
      ...(body === undefined ? {} : { "content-type": "application/json; charset=utf-8" }),
      ...headers,
    },
    body,
  });
}

function serviceFixture() {
  const service: Pseud0WebLoginService<{ id: string }, Response> = {
    metadata: vi.fn(async () => ({
      version: 1,
      domain: "login.example.org",
      displayName: "Example",
      publicKey: "p".repeat(43),
      signature: "q".repeat(86),
    })),
    createBrowserLogin: vi.fn(async () => ({
      session: SESSION,
      browser_secret: SECRET,
      exp: 1_800_000_000_000,
      qr: "pseud0://web-login?test",
    })),
    status: vi.fn(async (session) => ({
      session,
      status: "pending",
      exp: 1_800_000_000_000,
    })),
    complete: vi.fn(async (_session, _secret, response) => {
      response.headers.append(
        "set-cookie",
        "__Host-session=opaque; Path=/; Secure; HttpOnly; SameSite=Lax",
      );
    }),
    cancel: vi.fn(async () => undefined),
    acceptAssertion: vi.fn(async () => ({
      sessionId: SESSION,
      status: "accepted",
      receivedAt: 1_800_000_000_000,
    })),
    acceptRevocation: vi.fn(async () => ({
      status: "already_accepted",
      receivedAt: 1_800_000_000_000,
    })),
  };
  return { service, handlers: createPseud0WebLoginRouteHandlers(service) };
}

describe("@pseud0/web-login-adapter-next", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("exports the Node runtime and all seven canonical paths", () => {
    expect(runtime).toBe("nodejs");
    expect(Object.values(PSEUD0_WEB_LOGIN_PATHS)).toHaveLength(7);
  });

  it("serves cacheable metadata as JSON", async () => {
    const { handlers } = serviceFixture();
    const response = await handlers.metadata.GET(
      new Request(`${ORIGIN}/.well-known/pseud0-web-login`),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(response.headers.get("cache-control")).toBe("public, max-age=300");
    expect((await response.json()).version).toBe(1);
  });

  it("creates a login only for a same-origin browser request", async () => {
    const { service, handlers } = serviceFixture();
    const response = await handlers.sessions.POST(browserRequest("/pseud0/web-login/sessions"));

    expect(response.status).toBe(201);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(service.createBrowserLogin).toHaveBeenCalledWith({ origin: ORIGIN });

    const crossSite = await handlers.sessions.POST(
      browserRequest("/pseud0/web-login/sessions", undefined, {
        origin: "https://attacker.example",
        "sec-fetch-site": "cross-site",
      }),
    );
    expect(crossSite.status).toBe(400);
    expect(service.createBrowserLogin).toHaveBeenCalledTimes(1);
  });

  it("requires Fetch Metadata by default but allows an explicit trusted-proxy opt-out", async () => {
    const { service } = serviceFixture();
    const request = new Request(`${ORIGIN}/pseud0/web-login/sessions`, {
      method: "POST",
      headers: { origin: ORIGIN },
    });

    const strict = createPseud0WebLoginRouteHandlers(service);
    expect((await strict.sessions.POST(request.clone())).status).toBe(400);

    const behindTrustedProxy = createPseud0WebLoginRouteHandlers(service, {
      requireFetchMetadata: false,
    });
    expect((await behindTrustedProxy.sessions.POST(request)).status).toBe(201);
  });

  it("strictly parses the browser secret for status", async () => {
    const { service, handlers } = serviceFixture();
    const context = { params: Promise.resolve({ session: SESSION }) };
    const response = await handlers.status.POST(
      browserRequest(
        `/pseud0/web-login/sessions/${SESSION}/status`,
        JSON.stringify({ browser_secret: SECRET }),
      ),
      context,
    );

    expect(response.status).toBe(200);
    expect(service.status).toHaveBeenCalledWith(SESSION, SECRET);

    const unknownField = await handlers.status.POST(
      browserRequest(
        `/pseud0/web-login/sessions/${SESSION}/status`,
        JSON.stringify({ browser_secret: SECRET, extra: true }),
      ),
      context,
    );
    expect(unknownField.status).toBe(400);

    const duplicateKey = await handlers.status.POST(
      browserRequest(
        `/pseud0/web-login/sessions/${SESSION}/status`,
        `{"browser_secret":"${SECRET}","browser_secret":"${SECRET}"}`,
      ),
      context,
    );
    expect(duplicateKey.status).toBe(400);
    expect(service.status).toHaveBeenCalledTimes(1);
  });

  it("delegates session issuance to the service response without a default session", async () => {
    const { service, handlers } = serviceFixture();
    const response = await handlers.complete.POST(
      browserRequest(
        `/pseud0/web-login/sessions/${SESSION}/complete`,
        JSON.stringify({ browser_secret: SECRET }),
      ),
      { params: { session: SESSION } },
    );

    expect(response.status).toBe(204);
    expect(response.headers.get("set-cookie")).toContain("__Host-session=opaque");
    expect(service.complete).toHaveBeenCalledOnce();
  });

  it("cancels a browser login and returns an empty no-store response", async () => {
    const { service, handlers } = serviceFixture();
    const response = await handlers.cancel.POST(
      browserRequest(
        `/pseud0/web-login/sessions/${SESSION}/cancel`,
        JSON.stringify({ browser_secret: SECRET }),
      ),
      { params: { session: SESSION } },
    );

    expect(response.status).toBe(204);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toBe("");
    expect(service.cancel).toHaveBeenCalledWith(SESSION, SECRET);
  });

  it("passes byte-identical callback bodies and headers to the Node service", async () => {
    const { service, handlers } = serviceFixture();
    const raw = '{ "version": 1,\r\n"idempotency": "unchanged" }';
    const response = await handlers.assertions.POST(
      new Request(`${ORIGIN}/pseud0/web-login/assertions`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "i".repeat(22),
        },
        body: raw,
      }),
    );

    expect(response.status).toBe(202);
    const [bytes, headers] = vi.mocked(service.acceptAssertion).mock.calls[0]!;
    expect(new TextDecoder().decode(bytes)).toBe(raw);
    expect(headers.get("idempotency-key")).toBe("i".repeat(22));
  });

  it("maps an idempotent revocation retry to HTTP 200", async () => {
    const { handlers } = serviceFixture();
    const response = await handlers.revocations.POST(
      new Request(`${ORIGIN}/pseud0/web-login/revocations`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      }),
    );

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect((await response.json()).status).toBe("already_accepted");
  });

  it("rejects callback bodies above 16 KiB before calling the service", async () => {
    const { service, handlers } = serviceFixture();
    const response = await handlers.assertions.POST(
      new Request(`${ORIGIN}/pseud0/web-login/assertions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "x".repeat(MAX_CALLBACK_BODY_BYTES + 1),
      }),
    );

    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toBe("application/problem+json");
    expect(service.acceptAssertion).not.toHaveBeenCalled();
  });

  it("maps public SDK errors to stable problem+json without sensitive details", async () => {
    const { service } = serviceFixture();
    vi.mocked(service.status).mockRejectedValueOnce(new Pseud0WebLoginError("request_not_found"));
    const handlers = createPseud0WebLoginRouteHandlers(service);
    const response = await handlers.status.POST(
      browserRequest(
        `/pseud0/web-login/sessions/${SESSION}/status`,
        JSON.stringify({ browser_secret: SECRET }),
      ),
      { params: { session: SESSION } },
    );
    const body = await response.json();

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toBe("application/problem+json");
    expect(body).toEqual({
      type: "https://pseud0.org/problems/request_not_found",
      title: "Request not found",
      status: 404,
      code: "request_not_found",
      retryable: false,
    });
    expect(JSON.stringify(body)).not.toContain(SECRET);
  });
});
