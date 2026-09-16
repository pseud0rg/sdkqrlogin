import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { Server } from "node:http";
import { buildApp } from "../src/server.js";

describe("Express example", () => {
  let server: Server;
  let origin: string;

  beforeAll(async () => {
    process.env.NODE_ENV = "test";
    server = (await buildApp()).listen(0, "127.0.0.1");
    await new Promise<void>((resolve) => server.once("listening", resolve));
    const address = server.address();
    if (!address || typeof address === "string") throw new Error("No test address");
    origin = `http://127.0.0.1:${address.port}`;
  });

  afterAll(() => new Promise<void>((resolve) => server.close(() => resolve())));

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
