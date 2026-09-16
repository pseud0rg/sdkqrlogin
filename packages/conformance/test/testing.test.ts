import { readFile } from "node:fs/promises";
import type { RelayRegistration } from "@pseud0/web-login-core";
import { describe, expect, it, vi } from "vitest";
import { createFakeRelayForTests } from "../src/testing.js";

const vectorsUrl = new URL("../../../test-vectors/web-login-v1.json", import.meta.url);

describe("test-only fake relay", () => {
  it("accepts valid registration without issuing trusted assertions", async () => {
    const vectors = JSON.parse(await readFile(vectorsUrl, "utf8")) as {
      registration: RelayRegistration;
    };
    const relay = createFakeRelayForTests({ testsOnly: true });
    const response = await relay.request({
      method: "POST",
      url: "https://relay.pseud0.org/v1/site-sessions",
      body: new TextEncoder().encode(JSON.stringify(vectors.registration)),
      expectedContentTypes: ["application/json"],
      maxResponseBytes: 1024,
    });

    expect(response.status).toBe(201);
    expect(relay.registrations).toEqual([vectors.registration.sessionId]);
    expect(relay).not.toHaveProperty("createAssertion");
    expect(relay).not.toHaveProperty("verifyAssertion");
  });

  it("is disabled under production NODE_ENV", () => {
    vi.stubEnv("NODE_ENV", "production");
    try {
      expect(() => createFakeRelayForTests({ testsOnly: true })).toThrow(/tests-only/u);
    } finally {
      vi.unstubAllEnvs();
    }
  });
});
