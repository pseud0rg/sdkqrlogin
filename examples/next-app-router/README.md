# Next.js App Router example

Run `npm run dev -w @pseud0/example-next-app-router`, then open
`http://127.0.0.1:3000`. The client component uses
`@pseud0/web-login-browser` and renders QR pixels locally.

Every canonical endpoint has its own App Router `route.ts`; each route module
literally exports `runtime = "nodejs"` and the matching `GET` or `POST`
function. The identity adapter stores only opaque local users, while the
session adapter demonstrates a rotated `Secure`, `HttpOnly`, `__Host-` cookie.

## Security boundary

The fake relay, fake approval route, localhost request bridge, in-memory
repository, identities, and ephemeral storage keys are test/development-only.
Any request-time use throws when `NODE_ENV=production`; do not deploy this
example.

There is no private-key fixture. The process generates a fresh Ed25519 key in
memory, or loads a PKCS#8 PEM from `PSEUD0_SITE_KEY_FILE`. The loader rejects
symlinks and, on POSIX, group/world access.

A production integration must remove `canonicalDevelopmentSessionRequest` and
`/__dev/approve`, use canonical HTTPS directly, connect the real relay, use
durable transactional persistence, load keys through a secret manager, and
connect the site's real identity and session systems.
