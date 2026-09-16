# Integration guide

## Server

Create a dedicated Ed25519 key and keep its private half in a secret manager or
protected file. Configure the canonical bare DNS domain explicitly; never infer
it from request headers.

Implement:

- `WebLoginRepository` with durable transactions, compare-and-set transitions,
  and unique replay constraints;
- `IdentityAdapter`, keyed only by the relay `sub`;
- `SessionAdapter`, issuing a rotated `Secure`, `HttpOnly`, `__Host-` cookie.

Create the service with `createPseud0WebLoginService`, then mount one framework
adapter at the canonical metadata, browser, assertion, and revocation paths.
Run `expireBefore(Date.now())` at least once per minute.

The included memory repository is test-only and throws unless explicitly
enabled for tests.

## Browser

Create the controller only after user interaction. Supply a local QR renderer:

```ts
const login = createPseud0QrLogin({
  basePath: "/pseud0/web-login",
  renderQr({ value, canvas }) {
    renderQrToCanvas(value, canvas);
  },
  successPath: "/",
});

login.state.subscribe(render);
await login.start();
```

The controller keeps `browser_secret` in a private closure. Do not copy protocol
values into URLs, browser storage, DOM attributes, analytics, logs, traces, or
error-report attachments.

Alternatively, register the accessible custom element and render it as:

```html
<pseud0-qr-login endpoint="/pseud0/web-login" success-path="/"></pseud0-qr-login>
```

The element does not load a third-party QR service. An application must provide
a local renderer.

## Operational requirements

- Serve HTTPS with TLS 1.2+, HSTS, a restrictive CSP and `frame-ancestors`.
- Require same-origin browser requests and validate Fetch Metadata.
- Independently rate-limit every endpoint and failed secret checks.
- Disable body capture and redact all protocol values.
- Coordinate site-key rotation after all old five-minute sessions expire.
- Keep relay JWKS overlap during relay signing-key rotation.

Synapse is transport only. It cannot replace the separately deployed relay.
This protocol uses neither OAuth/OIDC nor a site Matrix bot.

## Runnable examples

`examples/next-app-router`, `examples/express`, and `examples/fastify` mount all
seven canonical routes and include a local browser UI. They generate site,
relay, lookup, encryption, and session material at process startup; no private
key or identifier fixture is committed. A protected PKCS#8 PEM site key may be
loaded with `PSEUD0_SITE_KEY_FILE`.

These examples intentionally use a fake relay and the in-memory repository.
They throw on request-time use under `NODE_ENV=production`. Their localhost
origin bridges and `POST /__dev/approve` endpoints are strictly for local
testing and must be removed, not adapted, for production.
