# Express example

Run `npm run dev -w @pseud0/example-express`, then open
`http://127.0.0.1:3001`. The page uses the browser SDK, renders QR pixels
locally, and offers a development-only approval button.

The canonical router is mounted before any global body parser. The example
implements `IdentityAdapter` and `SessionAdapter`; its session adapter issues a
rotated `Secure`, `HttpOnly`, `__Host-` cookie.

## Security boundary

The relay, identities, cryptographic storage keys, site key fallback, and
repository are process-local demonstrations. The process throws when
`NODE_ENV=production`; they must never be deployed or used as a trust fallback.
No private key fixture exists. A fresh Ed25519 site key is generated in memory
on each run, or a PKCS#8 PEM key can be loaded from
`PSEUD0_SITE_KEY_FILE`. On POSIX, that file must have mode `0600` (or stricter)
and must not be a symlink.

For production, remove the local-origin validator and fake approval route, use
the adapter's canonical HTTPS origin policy, a real relay, a durable
transactional repository, a secret-manager key loader, and an application
session store.
