# Fastify example

Run `npm run dev -w @pseud0/example-fastify`, then open
`http://127.0.0.1:3002`. The scoped adapter plugin owns the seven canonical
routes and its raw callback parser. The page uses the browser SDK and a local QR
renderer.

`IdentityAdapter` stores only opaque development users. `SessionAdapter`
demonstrates a rotated `Secure`, `HttpOnly`, `__Host-` cookie.

## Security boundary

This process throws under `NODE_ENV=production`. Its fake relay, localhost
Origin rewrite, in-memory repository, identities, and approval route are
strictly local test/development infrastructure and are forbidden in production.

No key fixture is committed. By default a fresh Ed25519 key is generated only
in process memory. `PSEUD0_SITE_KEY_FILE` may instead point to a non-symlink
PKCS#8 PEM file; on POSIX it must be mode `0600` or stricter. Production
integration must replace all local infrastructure with the real relay, durable
transactional persistence, canonical HTTPS, a secret-manager key loader, and
the application's session store.
