import { type AddressInfo } from "node:net";
import express, { type Response } from "express";
import { Pseud0WebLoginError, type Pseud0WebLoginService } from "@pseud0/web-login-node";
import { afterEach, describe, expect, it, vi } from "vitest";
import { PSEUD0_WEB_LOGIN_MAX_BODY_BYTES, createPseud0WebLoginRouter } from "../src/index.js";

const DOMAIN = "login.example.org";
const ORIGIN = `https://${DOMAIN}`;
const SESSION = "abcdefghijklmnop";
const SECRET = "abcdefghijklmnopqrstuv";
const openServers: import("node:http").Server[] = [];

function fakeService(): Pseud0WebLoginService<{ id: string }, Response> {
  return {
    metadata: vi.fn(async () => ({
      version: 1,
      domain: DOMAIN,
      displayName: "Example",
      publicKey: "a".repeat(43),
      signature: "b".repeat(86),
    })),
    createBrowserLogin: vi.fn(async () => ({
      session: SESSION,
      browser_secret: SECRET,
      exp: 1_800_000_000_000,
      qr: "pseud0://web-login?example",
    })),
    status: vi.fn(async (session) => ({
      session,
      status: "pending",
      exp: 1_800_000_000_000,
    })),
    complete: vi.fn(async (_session, _secret, response) => {
      response.cookie("__Host-session", "opaque", {
        secure: true,
        httpOnly: true,
        sameSite: "lax",
        path: "/",
      });
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
}

async function serve(
  service: Pseud0WebLoginService<{ id: string }, Response>,
  validateBrowserRequest?: () => boolean | Promise<boolean>,
): Promise<string> {
  const app = express();
  app.use(
    createPseud0WebLoginRouter({
      domain: DOMAIN,
      service,
      ...(validateBrowserRequest ? { validateBrowserRequest } : {}),
    }),
  );
  const server = app.listen(0);
  openServers.push(server);
  await new Promise<void>((resolve) => server.once("listening", resolve));
  const address = server.address() as AddressInfo;
  return `http://127.0.0.1:${address.port}`;
}

function browserHeaders(): Record<string, string> {
  return {
    origin: ORIGIN,
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
  };
}

afterEach(async () => {
  await Promise.all(
    openServers
      .splice(0)
      .map((server) => new Promise<void>((resolve) => server.close(() => resolve()))),
  );
});

describe("Express adapter", () => {
  it("mounts every canonical route with protocol response semantics", async () => {
    const service = fakeService();
    const base = await serve(service);

    const metadata = await fetch(`${base}/.well-known/pseud0-web-login`);
    expect(metadata.status).toBe(200);
    expect(metadata.headers.get("cache-control")).toBe("public, max-age=300");
    expect(metadata.headers.get("content-type")).toContain("application/json");

    const created = await fetch(`${base}/pseud0/web-login/sessions`, {
      method: "POST",
      headers: browserHeaders(),
    });
    expect(created.status).toBe(201);
    expect(service.createBrowserLogin).toHaveBeenCalledWith({ origin: ORIGIN });

    const browserBody = JSON.stringify({ browser_secret: SECRET });
    const status = await fetch(`${base}/pseud0/web-login/sessions/${SESSION}/status`, {
      method: "POST",
      headers: {
        ...browserHeaders(),
        "content-type": "application/json",
      },
      body: browserBody,
    });
    expect(status.status).toBe(200);
    expect(service.status).toHaveBeenCalledWith(SESSION, SECRET);

    const completed = await fetch(`${base}/pseud0/web-login/sessions/${SESSION}/complete`, {
      method: "POST",
      headers: {
        ...browserHeaders(),
        "content-type": "application/json",
      },
      body: browserBody,
    });
    expect(completed.status).toBe(204);
    expect(completed.headers.get("set-cookie")).toContain("__Host-session=opaque");

    const cancelled = await fetch(`${base}/pseud0/web-login/sessions/${SESSION}/cancel`, {
      method: "POST",
      headers: {
        ...browserHeaders(),
        "content-type": "application/json",
      },
      body: browserBody,
    });
    expect(cancelled.status).toBe(204);

    const assertion = await fetch(`${base}/pseud0/web-login/assertions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": SECRET,
      },
      body: '{"signed": "bytes"}',
    });
    expect(assertion.status).toBe(202);

    const revocation = await fetch(`${base}/pseud0/web-login/revocations`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": SECRET,
      },
      body: '{"revoked": true}',
    });
    expect(revocation.status).toBe(200);

    for (const response of [created, status, completed, cancelled, assertion, revocation]) {
      expect(response.headers.get("cache-control")).toBe("no-store");
      expect(response.headers.get("x-content-type-options")).toBe("nosniff");
      expect(response.headers.get("content-security-policy")).toContain("default-src 'none'");
    }
  });

  it("passes byte-identical callback bodies and headers to the service", async () => {
    const service = fakeService();
    const base = await serve(service);
    const raw = '{\r\n  "signed": "\\u0061" \r\n}';

    await fetch(`${base}/pseud0/web-login/assertions`, {
      method: "POST",
      headers: {
        "content-type": "application/json",
        "idempotency-key": SECRET,
      },
      body: raw,
    });

    const call = vi.mocked(service.acceptAssertion).mock.calls[0];
    expect(Buffer.from(call?.[0] ?? []).equals(Buffer.from(raw, "utf8"))).toBe(true);
    expect(call?.[1].get("Idempotency-Key")).toBe(SECRET);
  });

  it("rejects oversized and non-strict browser bodies before service parsing", async () => {
    const service = fakeService();
    const base = await serve(service);
    const headers = { ...browserHeaders(), "content-type": "application/json" };

    const oversized = await fetch(`${base}/pseud0/web-login/sessions/${SESSION}/status`, {
      method: "POST",
      headers,
      body: "x".repeat(PSEUD0_WEB_LOGIN_MAX_BODY_BYTES + 1),
    });
    expect(oversized.status).toBe(400);
    expect(oversized.headers.get("content-type")).toContain("application/problem+json");

    const duplicate = await fetch(`${base}/pseud0/web-login/sessions/${SESSION}/status`, {
      method: "POST",
      headers,
      body: `{"browser_secret":"${SECRET}","browser_secret":"${SECRET}"}`,
    });
    expect(duplicate.status).toBe(400);

    const unknown = await fetch(`${base}/pseud0/web-login/sessions/${SESSION}/status`, {
      method: "POST",
      headers,
      body: `{"browser_secret":"${SECRET}","extra":true}`,
    });
    expect(unknown.status).toBe(400);
    expect(service.status).not.toHaveBeenCalled();
  });

  it("validates Origin and Fetch Metadata or delegates to an injected policy", async () => {
    const service = fakeService();
    const base = await serve(service);

    const crossSite = await fetch(`${base}/pseud0/web-login/sessions`, {
      method: "POST",
      headers: { origin: "https://attacker.example", "sec-fetch-site": "cross-site" },
    });
    expect(crossSite.status).toBe(400);
    expect(service.createBrowserLogin).not.toHaveBeenCalled();

    const callback = vi.fn(async () => true);
    const delegatedBase = await serve(service, callback);
    const delegated = await fetch(`${delegatedBase}/pseud0/web-login/sessions`, {
      method: "POST",
      headers: { origin: "https://trusted-proxy.invalid" },
    });
    expect(delegated.status).toBe(201);
    expect(callback).toHaveBeenCalledOnce();
  });

  it("maps SDK and unknown errors to secret-free problem documents", async () => {
    const service = fakeService();
    vi.mocked(service.status).mockRejectedValueOnce(new Pseud0WebLoginError("request_not_found"));
    vi.mocked(service.cancel).mockRejectedValueOnce(new Error(`must not leak ${SECRET}`));
    const base = await serve(service);
    const headers = { ...browserHeaders(), "content-type": "application/json" };
    const body = JSON.stringify({ browser_secret: SECRET });

    const missing = await fetch(`${base}/pseud0/web-login/sessions/${SESSION}/status`, {
      method: "POST",
      headers,
      body,
    });
    expect(missing.status).toBe(404);
    expect(await missing.json()).toEqual({
      type: "https://pseud0.org/problems/request_not_found",
      title: "Request not found",
      status: 404,
      code: "request_not_found",
      retryable: false,
    });

    const internal = await fetch(`${base}/pseud0/web-login/sessions/${SESSION}/cancel`, {
      method: "POST",
      headers,
      body,
    });
    expect(internal.status).toBe(500);
    const text = await internal.text();
    expect(text).not.toContain(SECRET);
    expect(JSON.parse(text).code).toBe("internal_error");
  });
});
