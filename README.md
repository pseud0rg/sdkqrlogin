# pseud0 web login JavaScript SDK

TypeScript integration kit for pseud0 QR login. It provides:

- `@pseud0/web-login-core`: runtime-neutral wire validation and canonical payloads;
- `@pseud0/web-login-node`: server orchestration, cryptography and persistence contracts;
- `@pseud0/web-login-browser`: framework-neutral browser controller and web component;
- adapters for Next.js App Router, Express and Fastify;
- reusable repository and HTTP conformance tests.

The website never connects to Matrix and never receives a Matrix ID. A trusted
backend is mandatory. The central pseud0 relay must register each request before
the browser receives a QR code.

## Requirements

- Node.js 20 or newer
- a dedicated Ed25519 site key pair
- a transactional `WebLoginRepository`
- identity and application-session adapters
- HTTPS at the configured canonical lower-case DNS domain

```sh
npm install
npm run build
npm test
```

See [`docs/integration.md`](docs/integration.md) for server and browser setup.

## Production status

This implementation must not be described as production-ready until the
conformance suite and a real staging E2EE flow through Android and the pseud0
relay have passed. The included in-memory repository and fake test facilities
are forbidden in production.
