import { parseQrUri, parseSiteMetadata } from "@pseud0/web-login-core";
import { describe, expect, it } from "vitest";

export interface TestSiteRequest {
  method?: string;
  headers?: Readonly<Record<string, string>>;
  body?: string;
}

export interface WebLoginHttpFixture {
  browser: {
    session: string;
    browserSecret: string;
    expiresAt: number;
  };
  assertion: {
    idempotencyKey: string;
    rawBody: string;
    /** A separately valid assertion reusing the same idempotency key/JTI. */
    conflictingRawBody: string;
  };
}

/**
 * A framework adapter test harness. It is test-only and must never point at a
 * production site or relay.
 */
export interface TestSite {
  fixture: WebLoginHttpFixture;
  request(path: string, init?: TestSiteRequest): Promise<Response>;
  advancePastExpiry(): void | Promise<void>;
  close?(): void | Promise<void>;
}

type JsonObject = Record<string, unknown>;

const contentType = (response: Response): string =>
  response.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase() ?? "";

async function json(response: Response): Promise<JsonObject> {
  return (await response.json()) as JsonObject;
}

function expectNoStore(response: Response): void {
  expect(response.headers.get("cache-control")?.toLowerCase()).toContain("no-store");
}

function expectProblemShape(body: JsonObject, status: number): void {
  expect(body).toMatchObject({
    type: expect.any(String),
    title: expect.any(String),
    status,
    code: expect.any(String),
    retryable: expect.any(Boolean),
  });
}

async function withSite(
  createTestSite: () => Promise<TestSite>,
  run: (site: TestSite) => Promise<void>,
): Promise<void> {
  const site = await createTestSite();
  try {
    await run(site);
  } finally {
    await site.close?.();
  }
}

const secretBody = (secret: string): string => JSON.stringify({ browser_secret: secret });

async function acceptFixtureAssertion(site: TestSite): Promise<Response> {
  return site.request("/pseud0/web-login/assertions", {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "idempotency-key": site.fixture.assertion.idempotencyKey,
    },
    body: site.fixture.assertion.rawBody,
  });
}

/**
 * Registers the framework-neutral HTTP parity tests in the current Vitest
 * suite. The factory must return an isolated, pre-registered fixture.
 */
export function defineWebLoginHttpContract(createTestSite: () => Promise<TestSite>): void {
  describe("web-login HTTP contract", () => {
    it("serves strict signed metadata with public caching", async () => {
      await withSite(createTestSite, async (site) => {
        const response = await site.request("/.well-known/pseud0-web-login");
        expect(response.status).toBe(200);
        expect(contentType(response)).toBe("application/json");
        expect(response.headers.get("cache-control")?.toLowerCase()).toContain("public");
        expect(response.headers.get("cache-control")?.toLowerCase()).toContain("max-age=");
        const rawMetadata = new Uint8Array(await response.arrayBuffer());
        expect(() => parseSiteMetadata(rawMetadata)).not.toThrow();
      });
    });

    it("creates an OpenAPI-compatible browser login without caching", async () => {
      await withSite(createTestSite, async (site) => {
        const response = await site.request("/pseud0/web-login/sessions", { method: "POST" });
        expect(response.status).toBe(201);
        expect(contentType(response)).toBe("application/json");
        expectNoStore(response);
        const body = await json(response);
        expect(Object.keys(body).sort()).toEqual(["browser_secret", "exp", "qr", "session"]);
        expect(body).toMatchObject({
          session: expect.stringMatching(/^[A-Za-z0-9_-]{16,128}$/),
          browser_secret: expect.stringMatching(/^[A-Za-z0-9_-]{22,128}$/),
          exp: expect.any(Number),
          qr: expect.stringMatching(/^pseud0:\/\/web-login\?/),
        });
        expect(() => parseQrUri(body.qr as string)).not.toThrow();
      });
    });

    it("keeps unknown sessions and incorrect secrets response-equivalent", async () => {
      await withSite(createTestSite, async (site) => {
        const wrongSecret = "Z".repeat(43);
        const known = await site.request(
          `/pseud0/web-login/sessions/${site.fixture.browser.session}/status`,
          {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: secretBody(wrongSecret),
          },
        );
        const unknown = await site.request(`/pseud0/web-login/sessions/${"U".repeat(22)}/status`, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: secretBody(wrongSecret),
        });
        const knownBody = await json(known);
        const unknownBody = await json(unknown);

        expect(known.status).toBe(404);
        expect(unknown.status).toBe(known.status);
        expect(contentType(known)).toBe("application/problem+json");
        expect(contentType(unknown)).toBe(contentType(known));
        expectNoStore(known);
        expectNoStore(unknown);
        expectProblemShape(knownBody, 404);
        expectProblemShape(unknownBody, 404);
        expect({
          code: unknownBody.code,
          retryable: unknownBody.retryable,
          status: unknownBody.status,
          title: unknownBody.title,
          type: unknownBody.type,
        }).toEqual({
          code: knownBody.code,
          retryable: knownBody.retryable,
          status: knownBody.status,
          title: knownBody.title,
          type: knownBody.type,
        });
        expect(JSON.stringify([knownBody, unknownBody])).not.toContain(wrongSecret);
      });
    });

    it("returns accepted, identical retry, then replay with HTTP parity", async () => {
      await withSite(createTestSite, async (site) => {
        const accepted = await acceptFixtureAssertion(site);
        expect(accepted.status).toBe(202);
        expect(contentType(accepted)).toBe("application/json");
        expectNoStore(accepted);
        expect(await json(accepted)).toMatchObject({ status: "accepted" });

        const retry = await acceptFixtureAssertion(site);
        expect(retry.status).toBe(200);
        expect(contentType(retry)).toBe("application/json");
        expectNoStore(retry);
        expect(await json(retry)).toMatchObject({ status: "already_accepted" });

        const replay = await site.request("/pseud0/web-login/assertions", {
          method: "POST",
          headers: {
            "content-type": "application/json",
            "idempotency-key": site.fixture.assertion.idempotencyKey,
          },
          body: site.fixture.assertion.conflictingRawBody,
        });
        expect(replay.status).toBe(409);
        expect(contentType(replay)).toBe("application/problem+json");
        expectNoStore(replay);
        const replayBody = await json(replay);
        expectProblemShape(replayBody, 409);
        expect(replayBody.code).toBe("assertion_replayed");
      });
    });

    it("completes a ready browser login exactly once", async () => {
      await withSite(createTestSite, async (site) => {
        expect((await acceptFixtureAssertion(site)).status).toBe(202);
        const path = `/pseud0/web-login/sessions/${site.fixture.browser.session}/complete`;
        const init = {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: secretBody(site.fixture.browser.browserSecret),
        };
        const first = await site.request(path, init);
        expect(first.status).toBe(204);
        expectNoStore(first);
        expect(await first.text()).toBe("");

        const second = await site.request(path, init);
        expect(second.status).toBe(409);
        expect(contentType(second)).toBe("application/problem+json");
        expectNoStore(second);
        const body = await json(second);
        expectProblemShape(body, 409);
        expect(body.code).toBe("request_already_used");
      });
    });

    it("reports expiry at status and refuses completion", async () => {
      await withSite(createTestSite, async (site) => {
        await site.advancePastExpiry();
        const statusPath = `/pseud0/web-login/sessions/${site.fixture.browser.session}/status`;
        const init = {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: secretBody(site.fixture.browser.browserSecret),
        };
        const status = await site.request(statusPath, init);
        expect(status.status).toBe(200);
        expect(contentType(status)).toBe("application/json");
        expectNoStore(status);
        expect(await json(status)).toMatchObject({
          session: site.fixture.browser.session,
          status: "expired",
          exp: site.fixture.browser.expiresAt,
        });

        const completion = await site.request(
          `/pseud0/web-login/sessions/${site.fixture.browser.session}/complete`,
          init,
        );
        expect(completion.status).toBe(409);
        expect(contentType(completion)).toBe("application/problem+json");
        expectNoStore(completion);
        const body = await json(completion);
        expectProblemShape(body, 409);
        expect(body.code).toBe("request_expired");
      });
    });
  });
}
