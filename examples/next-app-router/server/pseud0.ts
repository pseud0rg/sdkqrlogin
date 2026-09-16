import { randomBytes } from "node:crypto";
import { createPseud0WebLoginRouteHandlers } from "@pseud0/web-login-adapter-next";
import { createExampleService } from "./example-service";

type Backend = Awaited<ReturnType<typeof createExampleService<Response>>>;

declare global {
  var __pseud0ExampleBackend: Promise<Backend> | undefined;
}

async function getBackend(): Promise<Backend> {
  if (process.env.NODE_ENV === "production") {
    throw new Error("The fake relay example is forbidden in production");
  }
  globalThis.__pseud0ExampleBackend ??= createExampleService<Response>((_user, response) => {
    response.headers.append(
      "set-cookie",
      `__Host-example-session=${randomBytes(32).toString("base64url")}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    );
  });
  return globalThis.__pseud0ExampleBackend;
}

export async function getHandlers() {
  const { service } = await getBackend();
  return createPseud0WebLoginRouteHandlers(service);
}

export function canonicalDevelopmentSessionRequest(request: Request): Request {
  if (process.env.NODE_ENV === "production") {
    throw new Error("The localhost development bridge is forbidden in production");
  }
  const url = new URL(request.url);
  url.protocol = "https:";
  url.hostname = "login.example.test";
  url.port = "";
  const headers = new Headers(request.headers);
  headers.set("origin", url.origin);
  return new Request(url, { method: request.method, headers });
}

export async function approveLatest(request: Request): Promise<void> {
  const { fakeRelay } = await getBackend();
  await fakeRelay.approve(new URL(request.url).origin);
}
