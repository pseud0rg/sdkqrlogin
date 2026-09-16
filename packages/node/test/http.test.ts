import { afterEach, describe, expect, it, vi } from "vitest";
import { createRestrictedHttpClient } from "../src/index.js";

const url = "https://relay.pseud0.org/.well-known/jwks.json";
const request = {
  method: "GET" as const,
  url,
  expectedContentTypes: ["application/json"],
  maxResponseBytes: 16,
};

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("restricted HTTP client", () => {
  it("rejects redirects", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response("{}", {
            status: 302,
            headers: { "content-type": "application/json", location: "https://example.org" },
          }),
      ),
    );
    const client = createRestrictedHttpClient({ allowedUrls: [url] });
    await expect(client.request(request)).rejects.toMatchObject({ code: "relay_unavailable" });
  });

  it("rejects wrong content types and oversized bodies", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        new Response("{}", {
          status: 200,
          headers: { "content-type": "text/plain" },
        }),
      )
      .mockResolvedValueOnce(
        new Response("x".repeat(17), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
      );
    vi.stubGlobal("fetch", fetchMock);
    const client = createRestrictedHttpClient({ allowedUrls: [url] });
    await expect(client.request(request)).rejects.toMatchObject({ code: "relay_unavailable" });
    await expect(client.request(request)).rejects.toMatchObject({ code: "relay_unavailable" });
  });

  it("rejects non-allowlisted URLs before network access", async () => {
    const fetchMock = vi.fn();
    vi.stubGlobal("fetch", fetchMock);
    const client = createRestrictedHttpClient({ allowedUrls: [url] });
    await expect(client.request({ ...request, url: "https://example.org/" })).rejects.toMatchObject(
      { code: "relay_unavailable" },
    );
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("enforces the total timeout", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        (_url: URL, init: RequestInit) =>
          new Promise<Response>((_resolve, reject) => {
            init.signal?.addEventListener("abort", () =>
              reject(new DOMException("aborted", "AbortError")),
            );
          }),
      ),
    );
    const client = createRestrictedHttpClient({ allowedUrls: [url], totalTimeoutMs: 5 });
    await expect(client.request(request)).rejects.toMatchObject({
      code: "relay_unavailable",
      retryable: true,
    });
  });
});
