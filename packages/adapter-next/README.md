# @pseud0/web-login-adapter-next

Web-standard route handlers for Next.js App Router. The package does not import
Next.js and requires the Node runtime.

Create the handlers once, then export the matching method from each of the seven
canonical route files:

```ts
import { createPseud0WebLoginRouteHandlers } from "@pseud0/web-login-adapter-next";
import { service } from "@/server/pseud0";

export const runtime = "nodejs";
export const { POST } = createPseud0WebLoginRouteHandlers(service).assertions;
```

Use `metadata`, `sessions`, `status`, `complete`, `cancel`, `assertions`, and
`revocations` for their respective canonical paths. Next.js requires the
literal `runtime` export in every route module so its static analysis selects
Node rather than Edge.

Browser POST handlers require exact same-origin `Origin` and
`Sec-Fetch-Site: same-origin` headers by default. If a trusted reverse proxy
removes Fetch Metadata, pass `{ requireFetchMetadata: false }`; origin checking
remains mandatory.

Relay callback bodies are streamed with a hard 16 KiB limit and passed to the
Node service byte-for-byte. Session cookie issuance is exclusively delegated to
the service's configured `SessionAdapter`.
