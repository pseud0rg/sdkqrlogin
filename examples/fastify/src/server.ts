import { randomBytes } from "node:crypto";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import Fastify, { type FastifyReply } from "fastify";
import QRCode from "qrcode";
import pseud0WebLoginFastify from "@pseud0/web-login-adapter-fastify";
import { createExampleService } from "./example-service.js";

const browserModule = fileURLToPath(import.meta.resolve("@pseud0/web-login-browser"));

const page = `<!doctype html>
<html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<title>pseud0 Fastify example</title>
<style>body{font:16px system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}canvas{display:block;margin:1rem 0}button{margin:.5rem .5rem .5rem 0;padding:.6rem 1rem}</style>
<h1>Local Fastify QR login</h1><p>The browser SDK renders this QR locally.</p>
<canvas id="qr" width="320" height="320" aria-label="pseud0 login QR code"></canvas>
<p id="status" role="status" aria-live="polite">Idle</p>
<button id="start">Start login</button><button id="approve" disabled>Simulate local approval</button>
<script type="module">
import { createPseud0QrLogin } from "/vendor/pseud0-browser.js";
const status = document.querySelector("#status"); const approve = document.querySelector("#approve");
const login = createPseud0QrLogin({
  async renderQr({ value, canvas, signal }) {
    const response = await fetch("/__dev/render-qr", {
      method: "POST", body: value, signal, headers: { "content-type": "text/plain" }
    });
    const image = new Image(); const url = URL.createObjectURL(await response.blob());
    await new Promise((resolve, reject) => {
      image.onload = resolve; image.onerror = reject; image.src = url;
    });
    canvas.getContext("2d").drawImage(image, 0, 0, 320, 320); URL.revokeObjectURL(url);
  },
  canvas: document.querySelector("#qr"), successPath: "/"
});
login.state.subscribe((state) => { status.textContent = state.status; approve.disabled = state.status !== "waiting"; });
document.querySelector("#start").addEventListener("click", () => void login.start());
approve.addEventListener("click", async () => {
  approve.disabled = true;
  if (!(await fetch("/__dev/approve", { method: "POST" })).ok) status.textContent = "Local approval failed";
});
</script></html>`;

export async function buildApp() {
  if (process.env.NODE_ENV === "production") {
    throw new Error("The local fake relay example is forbidden in production");
  }
  const app = Fastify({ logger: false });
  const { service, fakeRelay } = await createExampleService<FastifyReply>((_user, reply) => {
    reply.header(
      "set-cookie",
      `__Host-example-session=${randomBytes(32).toString("base64url")}; Path=/; HttpOnly; Secure; SameSite=Lax`,
    );
  });

  // Development bridge for localhost HTTP. A real deployment must not rewrite
  // Origin and must use the adapter's configured canonical HTTPS origin.
  app.addHook("onRequest", async (request) => {
    if (
      process.env.NODE_ENV !== "production" &&
      request.url.startsWith("/pseud0/web-login/") &&
      /^http:\/\/(?:127\.0\.0\.1|localhost):\d+$/.test(request.headers.origin ?? "")
    ) {
      request.headers.origin = "https://login.example.test";
    }
  });
  await app.register(pseud0WebLoginFastify, {
    browserOrigin: "https://login.example.test",
    service,
  });

  app.post("/__dev/approve", async (request, reply) => {
    await fakeRelay.approve(`http://${request.headers.host}`);
    return reply.code(204).send();
  });
  app.post("/__dev/render-qr", { bodyLimit: 2_048 }, async (request: { body?: unknown }, reply) => {
    if (typeof request.body !== "string" || !request.body.startsWith("pseud0://web-login?")) {
      return reply.code(400).send();
    }
    return reply.type("image/svg+xml").send(await QRCode.toString(request.body, { type: "svg" }));
  });
  app.get("/vendor/pseud0-browser.js", async (_request, reply) =>
    reply.type("text/javascript").send(await readFile(browserModule)),
  );
  app.get("/", async (_request, reply) => reply.type("text/html").send(page));
  return app;
}

if (process.env.NODE_ENV !== "test") {
  const port = Number(process.env.PORT ?? 3002);
  const app = await buildApp();
  await app.listen({ port, host: "127.0.0.1" });
  console.log(`Development-only example: http://127.0.0.1:${port}`);
}
