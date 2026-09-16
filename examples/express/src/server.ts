import { randomBytes } from "node:crypto";
import { fileURLToPath } from "node:url";
import express, { type Response } from "express";
import QRCode from "qrcode";
import { createPseud0WebLoginRouter } from "@pseud0/web-login-adapter-express";
import { createExampleService } from "./example-service.js";

const browserModule = fileURLToPath(import.meta.resolve("@pseud0/web-login-browser"));

const page = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width">
<title>pseud0 Express example</title>
<style>body{font:16px system-ui;max-width:42rem;margin:3rem auto;padding:0 1rem}canvas{display:block;margin:1rem 0}button{margin:.5rem .5rem .5rem 0;padding:.6rem 1rem}</style>
<h1>Local Express QR login</h1>
<p>This page uses the browser SDK and renders the QR locally.</p>
<canvas id="qr" width="320" height="320" aria-label="pseud0 login QR code"></canvas>
<p id="status" role="status" aria-live="polite">Idle</p>
<button id="start">Start login</button><button id="approve" disabled>Simulate local approval</button>
<script type="module">
import { createPseud0QrLogin } from "/vendor/pseud0-browser.js";
const status = document.querySelector("#status");
const approve = document.querySelector("#approve");
const login = createPseud0QrLogin({
  async renderQr({ value, canvas, signal }) {
    const response = await fetch("/__dev/render-qr", {
      method: "POST", body: value, signal, headers: { "content-type": "text/plain" }
    });
    const image = new Image();
    const url = URL.createObjectURL(await response.blob());
    await new Promise((resolve, reject) => {
      image.onload = resolve; image.onerror = reject; image.src = url;
    });
    canvas.getContext("2d").drawImage(image, 0, 0, 320, 320);
    URL.revokeObjectURL(url);
  },
  canvas: document.querySelector("#qr"),
  successPath: "/"
});
login.state.subscribe((state) => {
  status.textContent = state.status;
  approve.disabled = state.status !== "waiting";
});
document.querySelector("#start").addEventListener("click", () => void login.start());
approve.addEventListener("click", async () => {
  approve.disabled = true;
  const response = await fetch("/__dev/approve", { method: "POST" });
  if (!response.ok) status.textContent = "Local approval failed";
});
</script>
</html>`;

export async function buildApp() {
  if (process.env.NODE_ENV === "production") {
    throw new Error("The local fake relay example is forbidden in production");
  }

  const app = express();
  const { service, fakeRelay } = await createExampleService<Response>((_user, response) => {
    response.cookie("__Host-example-session", randomBytes(32).toString("base64url"), {
      httpOnly: true,
      secure: true,
      sameSite: "lax",
      path: "/",
    });
  });

  // This must be mounted before any global JSON parser so callback bytes stay exact.
  app.use(
    createPseud0WebLoginRouter({
      domain: "login.example.test",
      service,
      // Development bridge: browsers use localhost HTTP. Production code must
      // retain the adapter's default canonical HTTPS origin validation.
      validateBrowserRequest: ({ request }) =>
        process.env.NODE_ENV !== "production" &&
        /^http:\/\/(?:127\.0\.0\.1|localhost):\d+$/.test(request.get("origin") ?? ""),
    }),
  );

  app.post("/__dev/approve", async (request, response, next) => {
    try {
      await fakeRelay.approve(`${request.protocol}://${request.get("host")}`);
      response.status(204).end();
    } catch (error) {
      next(error);
    }
  });
  app.post(
    "/__dev/render-qr",
    express.text({ type: "text/plain", limit: "2kb" }),
    async (request, response) => {
      if (typeof request.body !== "string" || !request.body.startsWith("pseud0://web-login?")) {
        response.status(400).end();
        return;
      }
      response.type("image/svg+xml").send(await QRCode.toString(request.body, { type: "svg" }));
    },
  );
  app.get("/vendor/pseud0-browser.js", (_request, response) => response.sendFile(browserModule));
  app.get("/", (_request, response) => response.type("html").send(page));
  return app;
}

if (process.env.NODE_ENV !== "test") {
  const port = Number(process.env.PORT ?? 3001);
  const app = await buildApp();
  app.listen(port, "127.0.0.1", () => {
    console.log(`Development-only example: http://127.0.0.1:${port}`);
  });
}
