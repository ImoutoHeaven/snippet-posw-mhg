# snippet-posw-mhg

MHG PoW and Turnstile protection for Cloudflare Snippets and Workers. A PoW
challenge builds one MHG graph and Merkle commitment, opens the server-selected
samples, and receives proof or consume authorization.

## Build

Run the build and tests in a Linux Node.js `22.20.0` environment, such as a
Docker Desktop Linux container on Windows, with the locked dependency set:

```bash
npm ci
npm run build
npm test
```

The build writes `dist/pow_config_snippet.js`,
`dist/pow_core1_snippet.js`, and `dist/pow_core2_snippet.js`. Every snippet
must remain at or below the `32,768` byte hard limit.

## Runtime modules

- `pow-config.js`: matcher evaluation and signed per-request configuration.
- `pow-core-1.js`: business gate and PoW `/commit` and `/challenge` front end.
- `pow-core-2.js`: PoW `/open` verification and authenticated forwarding.
- `glue.js`: browser challenge orchestration and Worker bootstrap.
- `esm/esm.js`: browser module manifest for `mhg-worker.js`.
- `esm/mhg-worker.js`: one-graph MHG construction, commitment, and openings.
- `lib/`: shared matcher, PoW, transport, and verification code.
- `siteverify_provider/src/worker.js`: Turnstile and consume provider.
- `test/`: automated tests.

## Configuration

Configure `CONFIG` in `pow-config.js`. The canonical matcher example and the
complete key reference are in [docs/configuration.md](docs/configuration.md).

## Deploy

1. Set the same `CONFIG_SECRET` in `pow-config.js`, `pow-core-1.js`, and
   `pow-core-2.js`, then set route secrets and matchers from the configuration
   guide.
2. Build and deploy the matching Snippets in order:
   `pow-config -> pow-core-1 -> pow-core-2`.
3. The default `POW_GLUE_URL` and `POW_ESM_URL` point to this repository's
   `main` branch on jsDelivr. Operators can pin both URL controls to the same
   immutable published CDN reference. For self-hosting, set both controls to
   matching paths in the self-hosted release, keep the asset paths ahead of a
   protected catch-all rule, serve JavaScript with a JavaScript MIME type, and
   allow CORS when the asset host differs from the protected origin.
