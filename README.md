# snippet-posw-mhg

PoW and Turnstile gate for Cloudflare Snippets and Workers.

## Overview

`snippet-posw-mhg` protects routes with optional PoW and Turnstile checks.

## Quick Start

```bash
npm install
npm run build
```

`npm run build` writes snippet bundles to `dist/`.

## Files

- `pow-config.js`: rule matching and per-request config selection.
- `pow-core-1.js`: first gate stage for protected routes.
- `pow-core-2.js`: second gate stage and `/open` verification endpoint.
- `glue.js`: browser challenge and verification client helper.
- `esm/esm.js`: ESM entry that exports the PoW worker module URL.
- `esm/mhg-worker.js`: browser worker implementation used by the ESM runtime.
- `lib/`: shared libraries for matching, PoW, transport, and verification.
- `siteverify_provider/src/worker.js`: provider worker for Turnstile verification and consume support.
- `test/`: automated tests.

## Configuration

For complete configuration reference, see `docs/configuration.md`.

```js
const CONFIG = [
  {
    host: { eq: "example.com" },
    path: { glob: "/api/**" },
    when: {
      and: [{ method: { in: ["GET", "POST"] } }],
    },
    config: {
      POW_TOKEN: "replace-me",
      powcheck: true,
      turncheck: true,
      TURNSTILE_SITEKEY: "replace-me",
      TURNSTILE_SECRET: "replace-me",
    },
  },
];
```

## Deploy

Set shared secrets in the snippet files, then deploy in order: `pow-config -> pow-core-1 -> pow-core-2`.
