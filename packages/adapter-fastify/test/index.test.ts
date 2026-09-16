import { Pseud0WebLoginError } from "@pseud0/web-login-node";
import type { Pseud0WebLoginService, RelayCallbackResult } from "@pseud0/web-login-node";
import Fastify, { type FastifyReply } from "fastify";
import { afterEach, describe, expect, it, vi } from "vitest";
import { WEB_LOGIN_BODY_LIMIT, WEB_LOGIN_PATHS, pseud0WebLoginFastify } from "../src/index.js";

const ORIGIN = "https://example.org";
const SESSION = "abcdefghijklmnop";
const SECRET = "abcdefghijklmnopqrstuv";
const IDEMPOTENCY_KEY = "0123456789abcdefghijkl";

function callbackResult(status: RelayCallbackResult["status"] = "accepted"): RelayCallbackResult {
  return { sessionId: SESSION, status, receivedAt: 1_700_000_000_000 };
}

function serviceMock() {
  return {
    metadata: vi.fn(async () => ({
      version: 1 as const,
      domain: "example.org",
      displayName: "Example",
      publicKey: "a".repeat(43),
      signature: "b".repeat(86),
    })),
    createBrowserLogin: vi.fn(async () => ({
      session: SESSION,
      browser_secret: SECRET,
      exp: 1_700_000_060_000,
      qr: "pseud0://web-login?example",
    })),
    status: vi.fn(async () => ({
      session: SESSION,
      status: "pending" as const,
      exp: 1_700_000_060_000,
    })),
    complete: vi.fn(async (_session: string, _secret: string, reply: FastifyReply) => {
      reply.header("set-cookie", "__Host-session=opaque; Path=/; Secure; HttpOnly; SameSite=Lax");
    }),
    cancel: vi.fn(async () => undefined),
    acceptAssertion: vi.fn(async () => callbackResult()),
    acceptRevocation: vi.fn(async () => callbackResult()),
  };
}

type MockService = ReturnType<typeof serviceMock>;

async function testApp(service: MockService = serviceMock()) {
  const app = Fastify();
  await app.register(pseud0WebLoginFastify, {
    browserOrigin: ORIGIN,
    service: service as unknown as Pseud0WebLoginService<unknown, FastifyReply>,
  });
  await app.ready();
  return { app, service };
}

const browserHeaders = {
  origin: ORIGIN,
  "sec-fetch-site": "same-origin",
} as const;

const jsonBrowserHeaders = {
  ...browserHeaders,
  "content-type": "application/json",
} as const;

const apps: Array<ReturnType<typeof Fastify>> = [];

afterEach(async () => {
  await Promise.all(apps.splice(0).map((app) => app.close()));
});

describe("@pseud0/web-login-adapter-fastify", () => {
  it("mounts metadata and all browser canonical paths", async () => {
    const { app, service } = await testApp();
    apps.push(app);

    const metadata = await app.inject({
      method: "GET",
      url: WEB_LOGIN_PATHS.metadata,
    });
    expect(metadata.statusCode).toBe(200);
    expect(metadata.headers["cache-control"]).toBe("public, max-age=300");
    expect(metadata.headers["content-type"]).toMatch(/^application\/json/);

    const created = await app.inject({
      method: "POST",
      url: WEB_LOGIN_PATHS.sessions,
      headers: browserHeaders,
    });
    expect(created.statusCode).toBe(201);
    expect(service.createBrowserLogin).toHaveBeenCalledWith({ origin: ORIGIN });

    const body = { browser_secret: SECRET };
    const status = await app.inject({
      method: "POST",
      url: `/pseud0/web-login/sessions/${SESSION}/status`,
      headers: jsonBrowserHeaders,
      payload: body,
    });
    expect(status.statusCode).toBe(200);
    expect(service.status).toHaveBeenCalledWith(SESSION, SECRET);

    const completed = await app.inject({
      method: "POST",
      url: `/pseud0/web-login/sessions/${SESSION}/complete`,
      headers: jsonBrowserHeaders,
      payload: body,
    });
    expect(completed.statusCode).toBe(204);
    expect(completed.headers["set-cookie"]).toContain("__Host-session=opaque");
    expect(service.complete).toHaveBeenCalledWith(SESSION, SECRET, expect.anything());

    const cancelled = await app.inject({
      method: "POST",
      url: `/pseud0/web-login/sessions/${SESSION}/cancel`,
      headers: jsonBrowserHeaders,
      payload: body,
    });
    expect(cancelled.statusCode).toBe(204);
    expect(service.cancel).toHaveBeenCalledWith(SESSION, SECRET);

    for (const response of [created, status, completed, cancelled]) {
      expect(response.headers["cache-control"]).toBe("no-store");
      expect(response.headers["x-content-type-options"]).toBe("nosniff");
    }
  });

  it("passes byte-exact callback bodies and strict headers to the service", async () => {
    const { app, service } = await testApp();
    apps.push(app);
    const raw = Buffer.from('{ "jti" : "0123456789abcdefghijkl", "value":"é" }\n', "utf8");

    const assertion = await app.inject({
      method: "POST",
      url: WEB_LOGIN_PATHS.assertions,
      headers: {
        "content-type": "application/json; charset=utf-8",
        "idempotency-key": IDEMPOTENCY_KEY,
      },
      payload: raw,
    });

    expect(assertion.statusCode).toBe(202);
    const passedBody = service.acceptAssertion.mock.calls[0]?.[0];
    const passedHeaders = service.acceptAssertion.mock.calls[0]?.[1];
    expect(Buffer.from(passedBody ?? [])).toEqual(raw);
    expect(passedHeaders?.get("idempotency-key")).toBe(IDEMPOTENCY_KEY);

    service.acceptRevocation.mockResolvedValueOnce(callbackResult("already_accepted"));
    const revocation = await app.inject({
      method: "POST",
      url: WEB_LOGIN_PATHS.revocations,
      headers: {
        "content-type": "application/json",
        "idempotency-key": IDEMPOTENCY_KEY,
      },
      payload: raw,
    });
    expect(revocation.statusCode).toBe(200);
    expect(Buffer.from(service.acceptRevocation.mock.calls[0]?.[0] ?? [])).toEqual(raw);
  });

  it("enforces same-origin requests and Fetch Metadata", async () => {
    const { app, service } = await testApp();
    apps.push(app);

    for (const headers of [
      {},
      { origin: "https://attacker.example" },
      { origin: ORIGIN, "sec-fetch-site": "cross-site" },
    ]) {
      const response = await app.inject({
        method: "POST",
        url: WEB_LOGIN_PATHS.sessions,
        headers,
      });
      expect(response.statusCode).toBe(400);
      expect(response.headers["content-type"]).toMatch(/^application\/problem\+json/);
      expect(response.json()).toMatchObject({
        code: "invalid_request",
        retryable: false,
      });
    }
    expect(service.createBrowserLogin).not.toHaveBeenCalled();
  });

  it("keeps browser schemas closed and content types strict", async () => {
    const { app, service } = await testApp();
    apps.push(app);

    const unknownField = await app.inject({
      method: "POST",
      url: `/pseud0/web-login/sessions/${SESSION}/status`,
      headers: jsonBrowserHeaders,
      payload: { browser_secret: SECRET, extra: true },
    });
    expect(unknownField.statusCode).toBe(400);
    expect(unknownField.json()).toMatchObject({ code: "invalid_request" });

    const duplicateField = await app.inject({
      method: "POST",
      url: `/pseud0/web-login/sessions/${SESSION}/status`,
      headers: jsonBrowserHeaders,
      payload: `{"browser_secret":"${SECRET}","browser_secret":"${SECRET}"}`,
    });
    expect(duplicateField.statusCode).toBe(400);
    expect(duplicateField.json()).toMatchObject({ code: "invalid_request" });

    const wrongContentType = await app.inject({
      method: "POST",
      url: `/pseud0/web-login/sessions/${SESSION}/status`,
      headers: {
        ...browserHeaders,
        "content-type": "application/problem+json",
      },
      payload: JSON.stringify({ browser_secret: SECRET }),
    });
    expect(wrongContentType.statusCode).toBe(400);
    expect(wrongContentType.json()).toMatchObject({ code: "invalid_request" });
    expect(service.status).not.toHaveBeenCalled();
  });

  it("rejects callback bodies above 16 KiB before the service", async () => {
    const { app, service } = await testApp();
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: WEB_LOGIN_PATHS.assertions,
      headers: {
        "content-type": "application/json",
        "idempotency-key": IDEMPOTENCY_KEY,
      },
      payload: Buffer.alloc(WEB_LOGIN_BODY_LIMIT + 1, 0x20),
    });

    expect(response.statusCode).toBe(413);
    expect(response.json()).toMatchObject({
      status: 413,
      code: "invalid_request",
    });
    expect(service.acceptAssertion).not.toHaveBeenCalled();
  });

  it("maps SDK errors to non-sensitive problem+json", async () => {
    const service = serviceMock();
    service.status.mockRejectedValueOnce(new Pseud0WebLoginError("request_not_found"));
    const { app } = await testApp(service);
    apps.push(app);

    const response = await app.inject({
      method: "POST",
      url: `/pseud0/web-login/sessions/${SESSION}/status`,
      headers: jsonBrowserHeaders,
      payload: { browser_secret: SECRET },
    });

    expect(response.statusCode).toBe(404);
    expect(response.headers["content-type"]).toMatch(/^application\/problem\+json/);
    expect(response.json()).toEqual({
      type: "https://pseud0.org/problems/request_not_found",
      title: "Request not found",
      status: 404,
      code: "request_not_found",
      retryable: false,
    });
    expect(response.body).not.toContain(SESSION);
    expect(response.body).not.toContain(SECRET);
  });

  it("keeps its raw parser and error handler scoped", async () => {
    const app = Fastify();
    apps.push(app);
    const service = serviceMock();
    await app.register(pseud0WebLoginFastify, {
      browserOrigin: ORIGIN,
      service: service as unknown as Pseud0WebLoginService<unknown, FastifyReply>,
    });
    app.post("/outside", async (request) => ({
      isBuffer: Buffer.isBuffer(request.body),
      body: request.body,
    }));
    await app.ready();

    const response = await app.inject({
      method: "POST",
      url: "/outside",
      payload: { parent: true },
    });
    expect(response.statusCode).toBe(200);
    expect(response.json()).toEqual({
      isBuffer: false,
      body: { parent: true },
    });
  });
});
