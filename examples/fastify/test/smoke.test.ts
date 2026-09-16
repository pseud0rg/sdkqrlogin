import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { FastifyInstance } from "fastify";
import { buildApp } from "../src/server.js";

describe("Fastify example", () => {
  let app: FastifyInstance;
  let origin: string;

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    app = await buildApp();
    origin = await app.listen({ port: 0, host: "127.0.0.1" });
  });

  afterAll(async () => app.close());

  it("completes a development fake-relay login through canonical routes", async () => {
    expect((await fetch(origin)).status).toBe(200);
    expect((await fetch(`${origin}/.well-known/pseud0-web-login`)).status).toBe(200);
    const created = await fetch(`${origin}/pseud0/web-login/sessions`, {
      method: "POST",
      headers: { origin },
    });
    expect(created.status).toBe(201);
    const login = (await created.json()) as { session: string; browser_secret: string; qr: string };
    expect(login.qr).toMatch(/^pseud0:\/\//);
    expect((await fetch(`${origin}/__dev/approve`, { method: "POST" })).status).toBe(204);
    const headers = { origin, "content-type": "application/json" };
    const body = JSON.stringify({ browser_secret: login.browser_secret });
    const status = await fetch(`${origin}/pseud0/web-login/sessions/${login.session}/status`, {
      method: "POST",
      headers,
      body,
    });
    expect(await status.json()).toMatchObject({ status: "ready" });
    const completed = await fetch(`${origin}/pseud0/web-login/sessions/${login.session}/complete`, {
      method: "POST",
      headers,
      body,
    });
    expect(completed.status).toBe(204);
    expect(completed.headers.get("set-cookie")).toContain("__Host-example-session=");
  });
});
