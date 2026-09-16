import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  createPseud0QrLogin,
  definePseud0QrLoginElement,
  type Pseud0QrLoginState,
} from "../src/index.js";

const SESSION = "session_123456789";
const SECRET = "browser_secret_123456789";
const QR = "pseud0://web-login?v=1&domain=example.test&session=session_123456789";
const NOW = 1_800_000_000_000;
const EXPIRY = NOW + 60_000;

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function createResponse(): Response {
  return jsonResponse(
    {
      session: SESSION,
      browser_secret: SECRET,
      exp: EXPIRY,
      qr: QR,
    },
    201,
  );
}

function statusResponse(
  status: "pending" | "ready" | "denied" | "expired" | "cancelled" | "consumed",
): Response {
  return jsonResponse({ session: SESSION, status, exp: EXPIRY });
}

async function flush(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  await vi.advanceTimersByTimeAsync(0);
}

describe("createPseud0QrLogin", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
    vi.stubGlobal("window", {
      location: {
        href: "https://example.test/login",
        origin: "https://example.test",
        assign: vi.fn(),
      },
    });
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.useRealTimers();
  });

  it("keeps protected values out of observable state and completes when ready", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(createResponse())
      .mockResolvedValueOnce(statusResponse("ready"))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const renderQr = vi.fn();
    const observed: Pseud0QrLoginState[] = [];
    const navigate = vi.fn();
    const controller = createPseud0QrLogin({
      fetch: fetchMock,
      renderQr,
      random: () => 0.5,
      successPath: "/account",
      navigate,
    });
    controller.state.subscribe((value) => observed.push(value));

    const completed = controller.start();
    await flush();

    expect(renderQr).toHaveBeenCalledTimes(1);
    expect(renderQr.mock.calls[0]?.[0].value).toBe(QR);
    expect(JSON.stringify(observed)).not.toContain(QR);
    expect(JSON.stringify(observed)).not.toContain(SECRET);

    await vi.advanceTimersByTimeAsync(1_000);
    await completed;

    expect(controller.state.get()).toEqual({ status: "authenticated" });
    expect(fetchMock).toHaveBeenCalledTimes(3);
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      `https://example.test/pseud0/web-login/sessions/${SESSION}/status`,
    );
    expect(fetchMock.mock.calls[1]?.[1]?.body).toBe(JSON.stringify({ browser_secret: SECRET }));
    expect(fetchMock.mock.calls[2]?.[0]).toBe(
      `https://example.test/pseud0/web-login/sessions/${SESSION}/complete`,
    );
    expect(navigate).toHaveBeenCalledWith("https://example.test/account");
  });

  it("does not poll while the page is hidden", async () => {
    const visibility = new EventTarget() as EventTarget & {
      visibilityState: DocumentVisibilityState;
    };
    visibility.visibilityState = "hidden";
    vi.stubGlobal("document", visibility);
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(createResponse())
      .mockResolvedValueOnce(statusResponse("pending"))
      .mockResolvedValue(new Response(null, { status: 204 }));
    const controller = createPseud0QrLogin({
      fetch: fetchMock,
      renderQr: vi.fn(),
      random: () => 0.5,
    });

    const running = controller.start();
    await flush();
    await vi.advanceTimersByTimeAsync(30_000);
    expect(fetchMock).toHaveBeenCalledTimes(1);

    visibility.visibilityState = "visible";
    visibility.dispatchEvent(new Event("visibilitychange"));
    await vi.advanceTimersByTimeAsync(999);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);

    await controller.cancel();
    await running;
  });

  it("uses bounded exponential backoff and never polls below one second", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(createResponse())
      .mockRejectedValueOnce(new TypeError("offline"))
      .mockResolvedValueOnce(statusResponse("ready"))
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const controller = createPseud0QrLogin({
      fetch: fetchMock,
      renderQr: vi.fn(),
      pollIntervalMs: 10,
      maxPollIntervalMs: 2_000,
      jitterRatio: 0,
    });

    const completed = controller.start();
    await flush();
    await vi.advanceTimersByTimeAsync(999);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    await vi.advanceTimersByTimeAsync(1);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1_999);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    await vi.advanceTimersByTimeAsync(1);
    await completed;

    expect(fetchMock).toHaveBeenCalledTimes(4);
    expect(controller.state.get()).toEqual({ status: "authenticated" });
  });

  it("aborts polling, calls cancel, and drops protected state", async () => {
    const fetchMock = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(createResponse())
      .mockResolvedValueOnce(new Response(null, { status: 204 }));
    const controller = createPseud0QrLogin({
      fetch: fetchMock,
      renderQr: vi.fn(),
      random: () => 0.5,
    });
    const running = controller.start();
    await flush();

    await controller.cancel();
    await running;

    expect(controller.state.get()).toEqual({ status: "cancelled" });
    expect(fetchMock.mock.calls[1]?.[0]).toBe(
      `https://example.test/pseud0/web-login/sessions/${SESSION}/cancel`,
    );
    expect(fetchMock.mock.calls[1]?.[1]?.body).toBe(JSON.stringify({ browser_secret: SECRET }));
    expect(fetchMock.mock.calls[0]?.[1]?.signal).toBeInstanceOf(AbortSignal);
    expect(fetchMock.mock.calls[1]?.[1]?.signal).toBeInstanceOf(AbortSignal);
    expect(JSON.stringify(controller.state.get())).not.toContain(SECRET);
  });

  it("rejects cross-origin endpoints and success paths before fetching", () => {
    const fetchMock = vi.fn<typeof fetch>();
    expect(() =>
      createPseud0QrLogin({
        basePath: "https://attacker.test/api",
        fetch: fetchMock,
        renderQr: vi.fn(),
      }),
    ).toThrow(/same-origin/);
    expect(() =>
      createPseud0QrLogin({
        successPath: "https://attacker.test/done",
        fetch: fetchMock,
        renderQr: vi.fn(),
      }),
    ).toThrow(/same-origin/);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("exposes no QR or browser secret when a response is invalid", async () => {
    const fetchMock = vi.fn<typeof fetch>().mockResolvedValueOnce(
      jsonResponse(
        {
          session: SESSION,
          browser_secret: SECRET,
          exp: EXPIRY,
          qr: QR,
          unexpected: true,
        },
        201,
      ),
    );
    const renderQr = vi.fn();
    const controller = createPseud0QrLogin({
      fetch: fetchMock,
      renderQr,
    });

    await controller.start();

    expect(renderQr).not.toHaveBeenCalled();
    expect(controller.state.get()).toEqual({
      status: "error",
      retryable: false,
      code: "invalid_response",
    });
    expect(JSON.stringify(controller.state.get())).not.toContain(SECRET);
    expect(JSON.stringify(controller.state.get())).not.toContain(QR);
  });
});

describe("definePseud0QrLoginElement", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("registers once and does not access a QR service", () => {
    class FakeElement {}
    const registry = new Map<string, CustomElementConstructor>();
    const define = vi.fn((name: string, constructor: CustomElementConstructor): void => {
      registry.set(name, constructor);
    });
    vi.stubGlobal("HTMLElement", FakeElement);
    vi.stubGlobal("customElements", {
      define,
      get: (name: string) => registry.get(name),
    });

    definePseud0QrLoginElement();
    definePseud0QrLoginElement();

    expect(define).toHaveBeenCalledTimes(1);
    expect(define).toHaveBeenCalledWith("pseud0-qr-login", expect.any(Function));
  });
});
