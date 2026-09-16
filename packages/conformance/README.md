# @pseud0/web-login-conformance

Reusable Vitest contracts for web-login repositories and HTTP adapters.

```ts
import {
  defineWebLoginHttpContract,
  defineWebLoginRepositoryContract,
} from "@pseud0/web-login-conformance";

defineWebLoginRepositoryContract(async () => createIsolatedRepository());
defineWebLoginHttpContract(async () => createIsolatedTestSite());
```

Each factory invocation must return isolated state. `TestSite` supplies one
pre-registered browser fixture, two separately valid signed assertions sharing
an idempotency key/JTI, a request bridge, and a controllable test clock. The HTTP
contract checks metadata, creation, status privacy, callback retry/replay,
single consumption, expiry, content types, cache headers, and OpenAPI problem
parity.

`@pseud0/web-login-conformance/testing` exports a registration-only fake relay.
It requires `{ testsOnly: true }`, refuses to run under production
`NODE_ENV`, and intentionally has no assertion creation or trust API. The Node
in-memory repository has the same test-only restriction. Neither is a
production persistence or relay implementation.
