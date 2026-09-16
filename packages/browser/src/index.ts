export type Pseud0QrLoginState =
  | { readonly status: "idle" }
  | { readonly status: "creating" }
  | { readonly status: "waiting"; readonly expiresAt: number }
  | { readonly status: "completing" }
  | { readonly status: "authenticated" }
  | { readonly status: "denied" | "expired" | "cancelled" }
  | {
      readonly status: "error";
      readonly retryable: boolean;
      readonly code: string;
    };

export interface ReadonlyStore<T> {
  get(): T;
  subscribe(listener: (value: T) => void): () => void;
}

export interface Pseud0QrRendererInput {
  readonly value: string;
  readonly signal: AbortSignal;
  readonly canvas?: HTMLCanvasElement;
}

export type Pseud0QrRenderer = (input: Pseud0QrRendererInput) => void | Promise<void>;

export interface Pseud0QrLoginOptions {
  /** Same-origin path at which the canonical browser API is mounted. */
  readonly basePath?: string;
  /** Alias for basePath, primarily for the custom element vocabulary. */
  readonly endpoint?: string;
  readonly successPath?: string;
  readonly renderQr: Pseud0QrRenderer;
  readonly canvas?: HTMLCanvasElement;
  readonly pollIntervalMs?: number;
  readonly maxPollIntervalMs?: number;
  readonly jitterRatio?: number;
  readonly fetch?: typeof globalThis.fetch;
  readonly random?: () => number;
  readonly navigate?: (url: string) => void;
}

export interface Pseud0QrLoginController {
  readonly state: ReadonlyStore<Pseud0QrLoginState>;
  start(options?: { readonly signal?: AbortSignal }): Promise<void>;
  cancel(): Promise<void>;
  dispose(): void;
}

interface CreateResponse {
  session: string;
  browserSecret: string;
  expiresAt: number;
  qr: string;
}

type LoginStatus = "pending" | "ready" | "denied" | "expired" | "cancelled" | "consumed";

interface StatusResponse {
  status: LoginStatus;
  expiresAt: number;
}

interface PublicHttpError extends Error {
  code: string;
  retryable: boolean;
  httpStatus: number;
}

const MIN_POLL_MS = 1_000;
const DEFAULT_MAX_POLL_MS = 10_000;
const SESSION_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const SECRET_PATTERN = /^[A-Za-z0-9_-]{22,128}$/;
const QR_PATTERN = /^pseud0:\/\/web-login\?/;

function currentLocation(): Location {
  if (typeof window === "undefined" || window.location === undefined) {
    throw new Error("A browser location is required");
  }
  return window.location;
}

function sameOriginUrl(value: string, label: string): URL {
  const location = currentLocation();
  const url = new URL(value, location.href);
  if (url.origin !== location.origin || url.username !== "" || url.password !== "") {
    throw new TypeError(`${label} must be a same-origin URL`);
  }
  return url;
}

function apiBaseUrl(value: string): URL {
  const url = sameOriginUrl(value, "basePath");
  if (url.search !== "" || url.hash !== "") {
    throw new TypeError("basePath must not contain a query or fragment");
  }
  url.pathname = url.pathname.replace(/\/+$/, "");
  if (url.pathname === "") {
    throw new TypeError("basePath must contain a path");
  }
  return url;
}

function endpointUrl(base: URL, suffix: string): string {
  const url = new URL(base.href);
  url.pathname = `${base.pathname}${suffix}`;
  return url.href;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function hasExactKeys(value: Record<string, unknown>, expected: readonly string[]): boolean {
  const actual = Object.keys(value);
  return actual.length === expected.length && expected.every((key) => Object.hasOwn(value, key));
}

function parseCreateResponse(value: unknown): CreateResponse {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["session", "browser_secret", "exp", "qr"]) ||
    typeof value.session !== "string" ||
    !SESSION_PATTERN.test(value.session) ||
    typeof value.browser_secret !== "string" ||
    !SECRET_PATTERN.test(value.browser_secret) ||
    typeof value.exp !== "number" ||
    !Number.isSafeInteger(value.exp) ||
    value.exp < 0 ||
    typeof value.qr !== "string" ||
    value.qr.length > 2_048 ||
    !QR_PATTERN.test(value.qr)
  ) {
    throw makeHttpError("invalid_response", false, 0);
  }
  return {
    session: value.session,
    browserSecret: value.browser_secret,
    expiresAt: value.exp,
    qr: value.qr,
  };
}

function parseStatusResponse(value: unknown, session: string): StatusResponse {
  if (
    !isRecord(value) ||
    !hasExactKeys(value, ["session", "status", "exp"]) ||
    value.session !== session ||
    typeof value.status !== "string" ||
    !["pending", "ready", "denied", "expired", "cancelled", "consumed"].includes(value.status) ||
    typeof value.exp !== "number" ||
    !Number.isSafeInteger(value.exp) ||
    value.exp < 0
  ) {
    throw makeHttpError("invalid_response", false, 0);
  }
  return {
    status: value.status as LoginStatus,
    expiresAt: value.exp,
  };
}

function makeHttpError(code: string, retryable: boolean, httpStatus: number): PublicHttpError {
  const error = new Error("The web login request failed") as PublicHttpError;
  error.name = "Pseud0WebLoginError";
  error.code = code;
  error.retryable = retryable;
  error.httpStatus = httpStatus;
  return error;
}

function isPublicHttpError(error: unknown): error is PublicHttpError {
  return error instanceof Error && "code" in error && "retryable" in error && "httpStatus" in error;
}

async function responseError(response: Response): Promise<PublicHttpError> {
  let code = response.status === 429 ? "rate_limited" : "internal_error";
  let retryable = response.status === 429 || response.status >= 500;
  try {
    const body: unknown = await response.json();
    if (isRecord(body)) {
      if (typeof body.code === "string" && body.code.length <= 100) {
        code = body.code;
      }
      if (typeof body.retryable === "boolean") {
        retryable = body.retryable;
      }
    }
  } catch {
    // A malformed problem body never reveals response contents in the error.
  }
  return makeHttpError(code, retryable, response.status);
}

function abortError(): DOMException {
  return new DOMException("The operation was aborted", "AbortError");
}

function isAbortError(error: unknown): boolean {
  return error instanceof DOMException && error.name === "AbortError";
}

function createStore(initial: Pseud0QrLoginState): {
  readonly store: ReadonlyStore<Pseud0QrLoginState>;
  set(value: Pseud0QrLoginState): void;
} {
  let value = initial;
  const listeners = new Set<(state: Pseud0QrLoginState) => void>();
  return {
    store: {
      get: () => value,
      subscribe(listener) {
        listeners.add(listener);
        return () => listeners.delete(listener);
      },
    },
    set(next) {
      value = next;
      for (const listener of listeners) {
        listener(next);
      }
    },
  };
}

export function createPseud0QrLogin(options: Pseud0QrLoginOptions): Pseud0QrLoginController {
  if (typeof options.renderQr !== "function") {
    throw new TypeError("renderQr is required");
  }
  if (
    options.basePath !== undefined &&
    options.endpoint !== undefined &&
    options.basePath !== options.endpoint
  ) {
    throw new TypeError("basePath and endpoint must not conflict");
  }

  const base = apiBaseUrl(options.basePath ?? options.endpoint ?? "/pseud0/web-login");
  const successUrl =
    options.successPath === undefined
      ? undefined
      : sameOriginUrl(options.successPath, "successPath").href;
  const fetchImpl = options.fetch ?? globalThis.fetch;
  if (typeof fetchImpl !== "function") {
    throw new TypeError("fetch is required");
  }

  const baseDelay = Math.max(MIN_POLL_MS, Math.floor(options.pollIntervalMs ?? MIN_POLL_MS));
  const maxDelay = Math.max(
    baseDelay,
    Math.floor(options.maxPollIntervalMs ?? DEFAULT_MAX_POLL_MS),
  );
  const jitterRatio = Math.min(0.5, Math.max(0, options.jitterRatio ?? 0.2));
  const random = options.random ?? Math.random;
  const state = createStore({ status: "idle" });

  let browserSecret: string | undefined;
  let session: string | undefined;
  let expiresAt: number | undefined;
  let operation: AbortController | undefined;
  let activeStart: Promise<void> | undefined;
  let activeTimer: ReturnType<typeof setTimeout> | undefined;
  let cancellationInFlight: Promise<void> | undefined;
  let disposed = false;

  const clearTimer = (): void => {
    if (activeTimer !== undefined) {
      clearTimeout(activeTimer);
      activeTimer = undefined;
    }
  };

  const clearSensitive = (): void => {
    browserSecret = undefined;
    session = undefined;
    expiresAt = undefined;
  };

  const request = async (url: string, init: RequestInit): Promise<Response> => {
    const response = await fetchImpl(url, {
      ...init,
      credentials: "same-origin",
      redirect: "error",
      headers: {
        Accept: "application/json",
        ...init.headers,
      },
    });
    if (response.redirected) {
      throw makeHttpError("invalid_response", false, 0);
    }
    if (response.url !== "" && new URL(response.url).origin !== base.origin) {
      throw makeHttpError("invalid_response", false, 0);
    }
    return response;
  };

  const postSecret = async (
    action: "status" | "complete" | "cancel",
    currentSession: string,
    secret: string,
    signal: AbortSignal,
  ): Promise<Response> =>
    request(endpointUrl(base, `/sessions/${encodeURIComponent(currentSession)}/${action}`), {
      method: "POST",
      signal,
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ browser_secret: secret }),
    });

  const deliverCancellation = (currentSession: string, secret: string): Promise<void> => {
    if (cancellationInFlight !== undefined) {
      return cancellationInFlight;
    }
    const cancelController = new AbortController();
    const delivery = postSecret("cancel", currentSession, secret, cancelController.signal)
      .then(() => undefined)
      .catch(() => undefined);
    cancellationInFlight = delivery;
    return delivery;
  };

  const wait = (milliseconds: number, signal: AbortSignal): Promise<void> =>
    new Promise((resolve, reject) => {
      if (signal.aborted) {
        reject(abortError());
        return;
      }
      const onAbort = (): void => {
        clearTimer();
        reject(abortError());
      };
      activeTimer = setTimeout(() => {
        activeTimer = undefined;
        signal.removeEventListener("abort", onAbort);
        resolve();
      }, milliseconds);
      signal.addEventListener("abort", onAbort, { once: true });
    });

  const waitUntilVisible = (signal: AbortSignal): Promise<void> => {
    if (typeof document === "undefined" || document.visibilityState !== "hidden") {
      return Promise.resolve();
    }
    return new Promise((resolve, reject) => {
      const cleanup = (): void => {
        document.removeEventListener("visibilitychange", onVisibility);
        signal.removeEventListener("abort", onAbort);
      };
      const onVisibility = (): void => {
        if (document.visibilityState !== "hidden") {
          cleanup();
          resolve();
        }
      };
      const onAbort = (): void => {
        cleanup();
        reject(abortError());
      };
      document.addEventListener("visibilitychange", onVisibility);
      signal.addEventListener("abort", onAbort, { once: true });
    });
  };

  const jitteredDelay = (delay: number): number => {
    const boundedRandom = Math.min(1, Math.max(0, random()));
    const factor = 1 - jitterRatio + 2 * jitterRatio * boundedRandom;
    return Math.max(MIN_POLL_MS, Math.min(maxDelay, Math.round(delay * factor)));
  };

  const navigate = (): void => {
    if (successUrl === undefined) {
      return;
    }
    if (options.navigate !== undefined) {
      options.navigate(successUrl);
    } else {
      currentLocation().assign(successUrl);
    }
  };

  const initializeCreatedLogin = async (value: unknown, signal: AbortSignal): Promise<number> => {
    const created = parseCreateResponse(value);
    session = created.session;
    browserSecret = created.browserSecret;
    expiresAt = created.expiresAt;
    if (signal.aborted) {
      throw abortError();
    }
    const renderInput: Pseud0QrRendererInput =
      options.canvas === undefined
        ? { value: created.qr, signal }
        : { value: created.qr, signal, canvas: options.canvas };
    await options.renderQr(renderInput);
    if (signal.aborted) {
      throw abortError();
    }
    return created.expiresAt;
  };

  const run = async (externalSignal?: AbortSignal): Promise<void> => {
    const controller = new AbortController();
    operation = controller;
    cancellationInFlight = undefined;
    const onExternalAbort = (): void => {
      void cancel();
    };
    externalSignal?.addEventListener("abort", onExternalAbort, { once: true });

    try {
      if (externalSignal?.aborted === true) {
        await cancel();
        return;
      }
      state.set({ status: "creating" });
      const createResponse = await request(endpointUrl(base, "/sessions"), {
        method: "POST",
        signal: controller.signal,
      });
      if (!createResponse.ok) {
        throw await responseError(createResponse);
      }
      const createdExpiresAt = await initializeCreatedLogin(
        await createResponse.json(),
        controller.signal,
      );
      state.set({ status: "waiting", expiresAt: createdExpiresAt });

      let retryDelay = baseDelay;
      while (!controller.signal.aborted) {
        if (expiresAt !== undefined && Date.now() >= expiresAt) {
          state.set({ status: "expired" });
          clearSensitive();
          return;
        }
        await waitUntilVisible(controller.signal);
        await wait(jitteredDelay(retryDelay), controller.signal);
        await waitUntilVisible(controller.signal);

        const currentSession = session;
        const secret = browserSecret;
        if (currentSession === undefined || secret === undefined) {
          throw abortError();
        }

        try {
          const statusResponse = await postSecret(
            "status",
            currentSession,
            secret,
            controller.signal,
          );
          if (!statusResponse.ok) {
            throw await responseError(statusResponse);
          }
          const status = parseStatusResponse(await statusResponse.json(), currentSession);
          expiresAt = Math.min(expiresAt ?? status.expiresAt, status.expiresAt);
          retryDelay = baseDelay;

          if (status.status === "pending") {
            state.set({ status: "waiting", expiresAt: status.expiresAt });
            continue;
          }
          if (status.status === "ready") {
            state.set({ status: "completing" });
            const completed = await postSecret(
              "complete",
              currentSession,
              secret,
              controller.signal,
            );
            if (!completed.ok) {
              throw await responseError(completed);
            }
            state.set({ status: "authenticated" });
            clearSensitive();
            navigate();
            return;
          }
          if (status.status === "consumed") {
            state.set({ status: "authenticated" });
            clearSensitive();
            navigate();
            return;
          }
          state.set({ status: status.status });
          clearSensitive();
          return;
        } catch (error) {
          if (isAbortError(error)) {
            throw error;
          }
          const retryable = !isPublicHttpError(error) || error.retryable === true;
          if (!retryable) {
            throw error;
          }
          retryDelay = Math.min(maxDelay, retryDelay * 2);
        }
      }
    } catch (error) {
      if (isAbortError(error) || controller.signal.aborted) {
        const currentSession = session;
        const secret = browserSecret;
        if (state.store.get().status !== "cancelled") {
          state.set({ status: "cancelled" });
        }
        if (currentSession !== undefined && secret !== undefined) {
          await deliverCancellation(currentSession, secret);
        }
      } else {
        const publicError = isPublicHttpError(error)
          ? error
          : makeHttpError("internal_error", true, 0);
        state.set({
          status: "error",
          retryable: publicError.retryable,
          code: publicError.code,
        });
        const currentSession = session;
        const secret = browserSecret;
        if (currentSession !== undefined && secret !== undefined) {
          await deliverCancellation(currentSession, secret);
        }
      }
      clearSensitive();
    } finally {
      clearTimer();
      externalSignal?.removeEventListener("abort", onExternalAbort);
      if (operation === controller) {
        operation = undefined;
      }
    }
  };

  const start = (startOptions?: { readonly signal?: AbortSignal }): Promise<void> => {
    if (disposed) {
      return Promise.reject(new Error("The controller has been disposed"));
    }
    if (activeStart !== undefined) {
      return activeStart;
    }
    const promise = run(startOptions?.signal);
    activeStart = promise;
    void promise.finally(() => {
      if (activeStart === promise) {
        activeStart = undefined;
      }
    });
    return promise;
  };

  async function cancel(): Promise<void> {
    if (disposed && browserSecret === undefined) {
      return;
    }
    const currentSession = session;
    const secret = browserSecret;
    if (
      currentSession === undefined &&
      ["authenticated", "denied", "expired", "cancelled"].includes(state.store.get().status)
    ) {
      return;
    }
    operation?.abort();
    clearTimer();
    state.set({ status: "cancelled" });
    if (currentSession !== undefined && secret !== undefined) {
      await deliverCancellation(currentSession, secret);
    }
    clearSensitive();
  }

  const dispose = (): void => {
    if (disposed) {
      return;
    }
    disposed = true;
    operation?.abort();
    operation = undefined;
    clearTimer();
    clearSensitive();
  };

  return { state: state.store, start, cancel, dispose };
}

export interface Pseud0QrLoginElement extends HTMLElement {
  renderQr?: Pseud0QrRenderer;
  start(): Promise<void>;
  cancel(): Promise<void>;
}

const DEFAULT_LABELS = {
  title: "Sign in with pseud0",
  instructions: "Scan the QR code with the pseud0 app.",
  cancel: "Cancel",
  idle: "Ready to start.",
  creating: "Creating a secure login request.",
  waiting: "Waiting for approval in the pseud0 app.",
  completing: "Completing sign in.",
  authenticated: "Signed in.",
  denied: "The request was denied.",
  expired: "The request expired.",
  cancelled: "The request was cancelled.",
  error: "Sign in could not be completed.",
} as const;

export function definePseud0QrLoginElement(tagName = "pseud0-qr-login"): void {
  if (typeof customElements === "undefined" || typeof HTMLElement === "undefined") {
    throw new Error("Custom elements are not available");
  }
  if (customElements.get(tagName) !== undefined) {
    return;
  }

  class Pseud0QrLoginElementImplementation extends HTMLElement implements Pseud0QrLoginElement {
    renderQr?: Pseud0QrRenderer;
    #controller: Pseud0QrLoginController | undefined;
    #unsubscribe: (() => void) | undefined;
    #canvas: HTMLCanvasElement | undefined;
    #status: HTMLElement | undefined;
    #cancelButton: HTMLButtonElement | undefined;
    #started = false;

    connectedCallback(): void {
      if (this.shadowRoot === null) {
        this.#build();
      }
      queueMicrotask(() => {
        if (this.isConnected && !this.#started) {
          void this.start();
        }
      });
    }

    disconnectedCallback(): void {
      this.#unsubscribe?.();
      this.#unsubscribe = undefined;
      this.#controller?.dispose();
      this.#controller = undefined;
      this.#started = false;
    }

    async start(): Promise<void> {
      if (this.#started) {
        return this.#controller?.start();
      }
      this.#started = true;
      if (this.shadowRoot === null) {
        this.#build();
      }
      const renderer = this.renderQr;
      if (renderer === undefined || this.#canvas === undefined) {
        this.#showState({
          status: "error",
          retryable: false,
          code: "renderer_required",
        });
        return;
      }
      this.#controller = createPseud0QrLogin({
        endpoint: this.getAttribute("endpoint") ?? "/pseud0/web-login",
        successPath: this.getAttribute("success-path") ?? "/",
        renderQr: renderer,
        canvas: this.#canvas,
      });
      this.#unsubscribe = this.#controller.state.subscribe((value) => {
        this.#showState(value);
      });
      await this.#controller.start();
    }

    async cancel(): Promise<void> {
      await this.#controller?.cancel();
    }

    #label(name: keyof typeof DEFAULT_LABELS): string {
      return this.getAttribute(`${name}-label`) ?? DEFAULT_LABELS[name];
    }

    #showState(value: Pseud0QrLoginState): void {
      if (this.#status === undefined || this.#cancelButton === undefined) {
        return;
      }
      this.#status.textContent =
        value.status === "error" ? this.#label("error") : this.#label(value.status);
      this.#cancelButton.hidden = !["creating", "waiting", "completing"].includes(value.status);
    }

    #build(): void {
      const root = this.attachShadow({ mode: "open" });
      const style = document.createElement("style");
      style.textContent =
        ":host{display:block;color:CanvasText;background:Canvas;font:inherit}" +
        ".panel{max-width:28rem;padding:1rem;border:1px solid currentColor;border-radius:.5rem}" +
        "canvas{display:block;max-width:100%;margin:1rem auto}" +
        "button{font:inherit;padding:.6rem 1rem;color:ButtonText;background:ButtonFace;border:2px solid ButtonText;border-radius:.25rem}" +
        "button:focus-visible{outline:3px solid Highlight;outline-offset:3px}" +
        "[hidden]{display:none}";
      const panel = document.createElement("section");
      panel.className = "panel";
      panel.setAttribute("aria-labelledby", `${tagName}-title`);

      const title = document.createElement("h2");
      title.id = `${tagName}-title`;
      title.textContent = this.#label("title");
      const instructions = document.createElement("p");
      instructions.textContent = this.#label("instructions");
      const canvas = document.createElement("canvas");
      canvas.width = 320;
      canvas.height = 320;
      canvas.setAttribute("role", "img");
      canvas.setAttribute("aria-label", this.#label("instructions"));
      const status = document.createElement("p");
      status.setAttribute("role", "status");
      status.setAttribute("aria-live", "polite");
      status.setAttribute("aria-atomic", "true");
      status.textContent = this.#label("idle");
      const cancelButton = document.createElement("button");
      cancelButton.type = "button";
      cancelButton.textContent = this.#label("cancel");
      cancelButton.hidden = true;
      cancelButton.addEventListener("click", () => {
        void this.cancel();
      });

      panel.append(title, instructions, canvas, status, cancelButton);
      root.append(style, panel);
      this.#canvas = canvas;
      this.#status = status;
      this.#cancelButton = cancelButton;
    }
  }

  customElements.define(tagName, Pseud0QrLoginElementImplementation);
}
