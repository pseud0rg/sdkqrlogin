import { parseRelayRegistration } from "@pseud0/web-login-core";
import type { RestrictedHttpRequest, RestrictedHttpResponse } from "@pseud0/web-login-node";

export interface FakeRelayForTests {
  readonly registrations: readonly string[];
  request(request: RestrictedHttpRequest): Promise<RestrictedHttpResponse>;
}

/**
 * Minimal registration fake for local conformance tests only.
 *
 * It deliberately cannot create or bless relay assertions. Tests must provide
 * separately signed fixtures, so this helper can never become a trust fallback.
 */
export function createFakeRelayForTests(options: { testsOnly: true }): FakeRelayForTests {
  if (options.testsOnly !== true || process.env.NODE_ENV === "production") {
    throw new Error("The fake web-login relay is tests-only");
  }
  const registrations: string[] = [];

  return {
    registrations,
    async request(request) {
      if (
        request.method !== "POST" ||
        new URL(request.url).pathname !== "/v1/site-sessions" ||
        !request.body
      ) {
        throw new Error("The test-only fake relay supports registration only");
      }
      const registration = parseRelayRegistration(request.body);
      registrations.push(registration.sessionId);
      return {
        status: 201,
        headers: { "content-type": "application/json" },
        body: new TextEncoder().encode(
          JSON.stringify({
            sessionId: registration.sessionId,
            status: "registered",
            expiresAt: registration.exp,
          }),
        ),
      };
    },
  };
}
