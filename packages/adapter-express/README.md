# `@pseud0/web-login-adapter-express`

Express handlers for the canonical pseud0 web-login site endpoints.

```ts
import express from "express";
import { createPseud0WebLoginRouter } from "@pseud0/web-login-adapter-express";

const app = express();

// Mount this router before any app-wide express.json()/body parser.
app.use(
  createPseud0WebLoginRouter({
    domain: "login.example.org",
    service,
  }),
);

// Other application routes and their parsers come afterwards.
app.use(express.json());
```

Middleware order is security-critical. Relay assertion and revocation handlers
must receive the exact request bytes, so the adapter's scoped 16 KiB raw parser
must run before any JSON, text, or URL-encoded parser. If an earlier middleware
has consumed a body, the adapter rejects the request instead of reconstructing
bytes. The same scoped parser enforces the limit before strict browser JSON
parsing.

By default, browser endpoints require `Origin: https://<domain>`. If Fetch
Metadata headers are present, they must describe a same-origin fetch with an
empty destination. Deployments with a trusted proxy or another policy can
provide `validateBrowserRequest`; that callback replaces the default policy
and must use only trusted request data.

The adapter never creates an application session or writes a cookie itself.
The Node service passes the Express response to the configured
`SessionAdapter.issueSession`, which remains solely responsible for session
and cookie policy.
