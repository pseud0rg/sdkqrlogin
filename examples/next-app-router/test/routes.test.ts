import { beforeAll, describe, expect, it } from "vitest";
import { GET, runtime as metadataRuntime } from "../app/.well-known/pseud0-web-login/route";
import { POST, runtime as sessionsRuntime } from "../app/pseud0/web-login/sessions/route";
import { POST as acceptAssertion } from "../app/pseud0/web-login/assertions/route";
import { POST as approve } from "../app/__dev/approve/route";
import { POST as status } from "../app/pseud0/web-login/sessions/[session]/status/route";
import { POST as complete } from "../app/pseud0/web-login/sessions/[session]/complete/route";

describe("Next.js route exports", () => {
  beforeAll(() => {
    process.env.NODE_ENV = "test";
  });

  it("uses Node runtime and completes a fake-relay login", async () => {
    expect(metadataRuntime).toBe("nodejs");
    expect(sessionsRuntime).toBe("nodejs");
    expect((await GET(new Request("http://localhost/.well-known/pseud0-web-login"))).status).toBe(
      200,
    );
    const created = await POST(
      new Request("http://localhost/pseud0/web-login/sessions", {
        method: "POST",
        headers: { origin: "http://localhost", "sec-fetch-site": "same-origin" },
      }),
    );
    expect(created.status).toBe(201);
    const login = (await created.json()) as { session: string; browser_secret: string; qr: string };
    expect(login.qr).toMatch(/^pseud0:\/\//);

    const originalFetch = globalThis.fetch;
    globalThis.fetch = async (input, init) => {
      const request = new Request(input, init);
      if (new URL(request.url).pathname === "/pseud0/web-login/assertions") {
        return acceptAssertion(request);
      }
      return originalFetch(input, init);
    };
    try {
      expect((await approve(new Request("http://localhost/__dev/approve"))).status).toBe(204);
    } finally {
      globalThis.fetch = originalFetch;
    }

    const headers = {
      origin: "http://localhost",
      "sec-fetch-site": "same-origin",
      "content-type": "application/json",
    };
    const body = JSON.stringify({ browser_secret: login.browser_secret });
    const context = { params: Promise.resolve({ session: login.session }) };
    const current = await status(
      new Request(`http://localhost/pseud0/web-login/sessions/${login.session}/status`, {
        method: "POST",
        headers,
        body,
      }),
      context,
    );
    expect(await current.json()).toMatchObject({ status: "ready" });
    const completed = await complete(
      new Request(`http://localhost/pseud0/web-login/sessions/${login.session}/complete`, {
        method: "POST",
        headers,
        body,
      }),
      context,
    );
    expect(completed.status).toBe(204);
    expect(completed.headers.get("set-cookie")).toContain("__Host-example-session=");
  });
});
