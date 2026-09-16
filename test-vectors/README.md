# Public web-login v1 test vectors

Every value in this directory is deterministic, synthetic, and public. The
identifiers use explicit `test_` names; they are not Matrix IDs, production
subjects, sessions, nonces, assertions, or credentials.

`web-login-v1.json` contains complete signed protocol objects.
`web-login-v1-canonical.txt` contains the exact UTF-8 JCS payload for each
Ed25519 signature. `web-login-v1-qr.txt` contains the exact Android wire value.

The corresponding private test seed is intentionally not distributed. These
vectors are verification fixtures only and must not be used as authentication
credentials or as a relay trust fallback.
