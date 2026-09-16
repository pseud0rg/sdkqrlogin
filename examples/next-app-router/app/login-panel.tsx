"use client";

import { useEffect, useRef, useState } from "react";
import QRCode from "qrcode";
import {
  createPseud0QrLogin,
  type Pseud0QrLoginController,
  type Pseud0QrLoginState,
} from "@pseud0/web-login-browser";

export function LoginPanel() {
  const canvas = useRef<HTMLCanvasElement>(null);
  const controller = useRef<Pseud0QrLoginController>(null);
  const [state, setState] = useState<Pseud0QrLoginState>({ status: "idle" });

  useEffect(() => {
    if (!canvas.current) return;
    const login = createPseud0QrLogin({
      canvas: canvas.current,
      renderQr: ({ value, canvas: target }) => QRCode.toCanvas(target!, value, { width: 320 }),
      successPath: "/",
    });
    controller.current = login;
    const unsubscribe = login.state.subscribe(setState);
    return () => {
      unsubscribe();
      login.dispose();
      controller.current = null;
    };
  }, []);

  return (
    <section aria-labelledby="login-title">
      <h2 id="login-title">Sign in with pseud0</h2>
      <canvas ref={canvas} width={320} height={320} aria-label="pseud0 login QR code" />
      <p role="status" aria-live="polite">
        {state.status}
      </p>
      <button type="button" onClick={() => void controller.current?.start()}>
        Start login
      </button>
      <button
        type="button"
        disabled={state.status !== "waiting"}
        onClick={async () => {
          await fetch("/__dev/approve", { method: "POST" });
        }}
      >
        Simulate local approval
      </button>
    </section>
  );
}
