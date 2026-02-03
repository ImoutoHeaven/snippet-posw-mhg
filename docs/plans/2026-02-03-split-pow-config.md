# Split Pow Config Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Split matcher/config logic into a front snippet (`pow-config`) that emits a signed inner header, and slim `pow.js` to trust that header and execute PoW/Turnstile + business gating with fail-closed behavior.

**Architecture:** Two sequential Cloudflare Snippets. `pow-config` matches host/path (or `/__pow/*` ticket cfgId), normalizes config + derived binding data, signs and injects the payload into an inner header. `pow.js` verifies and consumes this payload, strips inner headers before forwarding, and handles all `/__pow/*` and gate logic. Missing/invalid header fails closed.

**Tech Stack:** Cloudflare Snippets runtime (fetch API), WebCrypto HMAC, node:test for local tests, esbuild + terser for minified output.

---

### Task 1: Define inner header schema + signature tests

**Files:**
- Create: `test/inner-config.test.js`
- Modify: `test/default-config.test.js`

**Step 1: Write the failing test**

```js
import test from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";

const b64u = (buf) =>
  Buffer.from(buf)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/u, "");

test("inner header signature required", async () => {
  const payload = b64u(Buffer.from("{\"v\":1}", "utf8"));
  const secret = "config-secret";
  const mac = b64u(crypto.createHmac("sha256", secret).update(payload).digest());

  assert.ok(payload.length > 0);
  assert.ok(mac.length > 0);
});
```

**Step 2: Run test to verify it fails**

Run: `node --test test/inner-config.test.js`
Expected: FAIL because no runtime verifier exists yet.

**Step 3: Write minimal implementation**

Add helper(s) in `pow.js` (and later `pow-config.js`) to compute/verify:

```js
const hmacSha256Base64UrlNoPad = async (secret, data) => {
  const bytes = await hmacSha256(secret, data);
  return base64UrlEncodeNoPad(bytes);
};
```

**Step 4: Run test to verify it passes**

Run: `node --test test/inner-config.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add test/inner-config.test.js pow.js
git commit -m "test: add inner header signature coverage"
```

### Task 2: Implement `pow-config.js` (matcher + normalization + signing)

**Files:**
- Create: `pow-config.js`

**Step 1: Write the failing test**

```js
test("pow-config injects signed header", async () => {
  const res = await handler(new Request("https://example.com/protected"));
  // expect modified request to include X-Pow-Inner + X-Pow-Inner-Mac
});
```

**Step 2: Run test to verify it fails**

Run: `node --test test/inner-config.test.js`
Expected: FAIL (no pow-config exists)

**Step 3: Write minimal implementation**

Implement in `pow-config.js`:

```js
const INNER_HEADER = "X-Pow-Inner";
const INNER_MAC = "X-Pow-Inner-Mac";
const CONFIG_SECRET = "replace-me";

const payload = base64UrlEncodeNoPad(utf8ToBytes(JSON.stringify({ v: 1, id, c, d })));
const mac = await hmacSha256Base64UrlNoPad(CONFIG_SECRET, payload);

const headers = new Headers(request.headers);
headers.delete(INNER_HEADER);
headers.delete(INNER_MAC);
headers.set(INNER_HEADER, payload);
headers.set(INNER_MAC, mac);
return fetch(new Request(request, { headers }));
```

Add host/path matcher + cfgId resolution for `/__pow/*` via ticket/cookie.

**Step 4: Run test to verify it passes**

Run: `node --test test/inner-config.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add pow-config.js test/inner-config.test.js
git commit -m "feat: add pow-config header injector"
```

### Task 3: Refactor `pow.js` to require inner header (fail-closed)

**Files:**
- Modify: `pow.js`
- Modify: `test/default-config.test.js`

**Step 1: Write the failing test**

```js
test("pow.js fails closed without inner header", async () => {
  const res = await handler(new Request("https://example.com/protected"));
  assert.equal(res.status, 500);
});
```

**Step 2: Run test to verify it fails**

Run: `node --test test/default-config.test.js`
Expected: FAIL (currently falls back to DEFAULTS)

**Step 3: Write minimal implementation**

Refactor `pow.js`:

```js
const readInnerPayload = async (request) => {
  const payload = request.headers.get(INNER_HEADER) || "";
  const mac = request.headers.get(INNER_MAC) || "";
  if (!payload || !mac) return null;
  const expected = await hmacSha256Base64UrlNoPad(CONFIG_SECRET, payload);
  if (!timingSafeEqual(expected, mac)) return null;
  const json = decoder.decode(base64UrlDecodeToBytes(payload) || new Uint8Array());
  return JSON.parse(json);
};
```

Use `inner.c` for config and `inner.d` for derived binding values. Strip `X-Pow-Inner*` before any `fetch()` to origin.

**Step 4: Run test to verify it passes**

Run: `node --test test/default-config.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add pow.js test/default-config.test.js
git commit -m "refactor: require signed inner config header"
```

### Task 4: Update build output to emit two snippets

**Files:**
- Modify: `build.mjs`

**Step 1: Write the failing test**

```js
test("build emits pow-config snippet", async () => {
  // run build.mjs and assert dist/pow_config_snippet.js exists
});
```

**Step 2: Run test to verify it fails**

Run: `node --test test/inner-config.test.js`
Expected: FAIL (no dist file)

**Step 3: Write minimal implementation**

In `build.mjs`:
- Build `pow-config.js` with `__COMPILED_CONFIG__` injected.
- Build `pow.js` with `__HTML_TEMPLATE__` injected.
- Output `dist/pow_config_snippet.js` and `dist/pow_snippet.js`.

**Step 4: Run test to verify it passes**

Run: `node build.mjs`
Expected: both files exist and size <= 32KB.

**Step 5: Commit**

```bash
git add build.mjs dist/pow_config_snippet.js dist/pow_snippet.js
git commit -m "build: emit pow-config and pow snippets"
```

### Task 5: End-to-end snippet chain tests

**Files:**
- Create: `test/snippet-chain.test.js`
- Modify: `test/pow-challenge-binding.test.js`

**Step 1: Write the failing test**

```js
test("pow-config -> pow.js chain sets and strips inner header", async () => {
  // simulate pow-config adding header then pow.js consuming it
  // assert final origin fetch has no X-Pow-Inner*
});
```

**Step 2: Run test to verify it fails**

Run: `node --test test/snippet-chain.test.js`
Expected: FAIL

**Step 3: Write minimal implementation**

Add test harness that:
- Injects `__COMPILED_CONFIG__` into pow-config
- Injects `__HTML_TEMPLATE__` into pow.js
- Stubs `globalThis.fetch` to pass request through pow.js after pow-config

**Step 4: Run test to verify it passes**

Run: `node --test test/snippet-chain.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add test/snippet-chain.test.js test/pow-challenge-binding.test.js
git commit -m "test: cover pow-config to pow chain"
```
