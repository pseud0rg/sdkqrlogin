import {
  Pseud0WebLoginError,
  type RestrictedHttpClient,
  type RestrictedHttpRequest,
} from "./types.js";

export interface NodeRestrictedHttpClientOptions {
  allowedUrls: readonly string[];
  totalTimeoutMs?: number;
}

export function createRestrictedHttpClient(
  options: NodeRestrictedHttpClientOptions,
): RestrictedHttpClient {
  const allowed = new Set(
    options.allowedUrls.map((entry) => {
      const url = new URL(entry);
      if (url.protocol !== "https:" || url.username || url.password || url.port || url.hash) {
        throw new Pseud0WebLoginError("internal_error");
      }
      return url.href;
    }),
  );

  return {
    async request(request: RestrictedHttpRequest) {
      let url: URL;
      try {
        url = new URL(request.url);
      } catch {
        throw new Pseud0WebLoginError("relay_unavailable", true);
      }
      if (
        !allowed.has(url.href) ||
        url.protocol !== "https:" ||
        url.username ||
        url.password ||
        url.port ||
        url.hash
      ) {
        throw new Pseud0WebLoginError("relay_unavailable");
      }
      const controller = new AbortController();
      const timeout = setTimeout(
        () => controller.abort(),
        request.timeoutMs ?? options.totalTimeoutMs ?? 5_000,
      );
      try {
        const response = await fetch(url, {
          method: request.method,
          ...(request.headers ? { headers: request.headers } : {}),
          ...(request.body ? { body: Buffer.from(request.body) } : {}),
          redirect: "manual",
          signal: controller.signal,
        });
        if (response.status >= 300 && response.status < 400) {
          throw new Pseud0WebLoginError("relay_unavailable");
        }
        if (response.status < 200 || response.status >= 300) {
          throw new Pseud0WebLoginError("relay_unavailable", response.status >= 500);
        }
        const contentType = response.headers
          .get("content-type")
          ?.split(";", 1)[0]
          ?.trim()
          .toLowerCase();
        if (!contentType || !request.expectedContentTypes.includes(contentType)) {
          throw new Pseud0WebLoginError("relay_unavailable");
        }
        const reader = response.body?.getReader();
        const chunks: Uint8Array[] = [];
        let size = 0;
        if (reader) {
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            size += value.byteLength;
            if (size > request.maxResponseBytes) {
              await reader.cancel();
              throw new Pseud0WebLoginError("relay_unavailable");
            }
            chunks.push(value);
          }
        }
        return {
          status: response.status,
          headers: Object.fromEntries(response.headers.entries()),
          body: Buffer.concat(chunks),
        };
      } catch (error) {
        if (error instanceof Pseud0WebLoginError) throw error;
        throw new Pseud0WebLoginError("relay_unavailable", true);
      } finally {
        clearTimeout(timeout);
      }
    },
  };
}
