# Config Matcher AOT Fast Path Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Speed up pow-config rule matching using AOT metadata and runtime fast paths without changing matcher behavior.

**Architecture:** Build step emits host/path/when metadata alongside regex. Runtime iterates rules in original order but uses exact/prefix/wildcard matchers before falling back to regex; when evaluation builds context lazily based on precomputed needs, and any ambiguous pattern falls back to legacy regex matching.

**Tech Stack:** Node.js (build + tests), Cloudflare Workers runtime (pow-config), Node test runner (`node --test`).

---

### Task 1: Collect when needs metadata

**Files:**
- Modify: `lib/when-compile.js`
- Test: `tests/when-compile.test.js`

**Step 1: Write the failing test**

```js
test("collectWhenNeeds reports used fields", () => {
  const input = {
    and: [
      { ua: "bot" },
      { header: { "x-test": { exists: true } } },
      { or: [{ cookie: { a: "1" } }, { query: { q: /x/ } }] },
      { not: { tls: true } },
      { ip: "203.0.113.0/24" },
      { country: "US" },
      { asn: "13335" },
      { path: "/healthz" },
      { method: "GET" },
    ],
  };
  const needs = collectWhenNeeds(input);
  assert.deepEqual(needs, {
    ua: true,
    header: true,
    cookie: true,
    query: true,
    tls: true,
    ip: true,
    country: true,
    asn: true,
    path: true,
    method: true,
  });
});
```

**Step 2: Run test to verify it fails**

Run: `node --test tests/when-compile.test.js`
Expected: FAIL with "collectWhenNeeds is not defined"

**Step 3: Write minimal implementation**

```js
export function collectWhenNeeds(input) {
  const needs = {};
  const visit = (node) => {
    if (!node) return;
    if (Array.isArray(node)) {
      node.forEach(visit);
      return;
    }
    if (node instanceof RegExp) return;
    if (typeof node !== "object") return;
    for (const [key, value] of Object.entries(node)) {
      if (key === "and" || key === "or") {
        visit(value);
        continue;
      }
      if (key === "not") {
        visit(value);
        continue;
      }
      needs[key] = true;
    }
  };
  visit(input);
  return needs;
}
```

**Step 4: Run test to verify it passes**

Run: `node --test tests/when-compile.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/when-compile.js tests/when-compile.test.js
git commit -m "feat: collect when condition needs"
```

### Task 2: Emit host/path metadata in compiled config

**Files:**
- Modify: `lib/build-config.js`
- Test: `tests/build-compiled-config.test.js`

**Step 1: Write the failing test**

```js
test("buildCompiledConfig emits matcher metadata", async () => {
  const configSource = `
    const CONFIG = [
      { pattern: "example.com/foo/**", when: { ua: "bot" }, config: { powcheck: true } },
      { pattern: "*.example.com/bar", config: { turncheck: true } },
    ];
  `;
  // write temp file, run buildCompiledConfig, parse JSON as in existing tests
  assert.equal(entry0.hostType, "exact");
  assert.equal(entry0.hostExact, "example.com");
  assert.equal(entry0.pathType, "prefix");
  assert.equal(entry0.pathPrefix, "/foo");
  assert.deepEqual(entry0.whenNeeds, { ua: true });

  assert.equal(entry1.hostType, "wildcard");
  assert.deepEqual(entry1.hostLabels, ["*", "example", "com"]);
  assert.equal(entry1.hostLabelCount, 3);
  assert.equal(entry1.pathType, "exact");
  assert.equal(entry1.pathExact, "/bar");
});
```

**Step 2: Run test to verify it fails**

Run: `node --test tests/build-compiled-config.test.js`
Expected: FAIL with "hostType is undefined"

**Step 3: Write minimal implementation**

- Add `analyzeHostPattern(pattern)` to return `{ hostType, hostExact, hostLabels, hostLabelCount }`.
- Add `analyzePathPattern(path)` to return `{ pathType, pathExact, pathPrefix }` where:
  - `exact` when no `*`
  - `prefix` when it ends with `/**` and has no other `*`
  - otherwise `regex`
- In `compileConfigEntry`, compute `whenNeeds = collectWhenNeeds(when)` and include metadata in compiled entry.
- Include new fields in JSON output so runtime can use them.

**Step 4: Run test to verify it passes**

Run: `node --test tests/build-compiled-config.test.js`
Expected: PASS

**Step 5: Commit**

```bash
git add lib/build-config.js tests/build-compiled-config.test.js
git commit -m "feat: emit matcher metadata in compiled config"
```

### Task 3: Runtime fast matcher with safe fallback

**Files:**
- Modify: `pow-config.js`
- Test: `tests/when-runtime.test.js`

**Step 1: Write the failing test**

```js
test("pickConfigWithId uses matcher metadata without changing results", () => {
  const compiled = [
    {
      host: { s: "^example\\.com$", f: "" },
      path: { s: "^/foo(?:/.*)?$", f: "" },
      hostType: "exact",
      hostExact: "example.com",
      pathType: "prefix",
      pathPrefix: "/foo",
      when: { ua: "bot" },
      whenNeeds: { ua: true },
      config: { powcheck: true },
    },
    {
      host: { s: "^[^.]*\\.example\\.com$", f: "" },
      path: { s: "^/bar$", f: "" },
      hostType: "wildcard",
      hostLabels: ["*", "example", "com"],
      hostLabelCount: 3,
      pathType: "exact",
      pathExact: "/bar",
      when: null,
      config: { turncheck: true },
    },
  ];
  const restore = __test.setCompiledConfigForTest(compiled);
  // Build a request for https://example.com/foo with UA "bot"
  // Expect cfgId 0, and for https://a.example.com/bar expect cfgId 1.
  restore();
});
```

**Step 2: Run test to verify it fails**

Run: `node --test tests/when-runtime.test.js`
Expected: FAIL with mismatch/undefined matcher metadata

**Step 3: Write minimal implementation**

- Extend COMPILED_CONFIG mapping to include `hostType`, `hostExact`, `hostLabels`, `hostLabelCount`, `pathType`, `pathExact`, `pathPrefix`, `whenNeeds`.
- Add `matchHostFast(host, rule)`:
  - `exact`: `host === hostExact`
  - `wildcard`: split host into labels once, compare against `hostLabels` with `*` wildcard
  - fallback: use `hostRegex`
- Add `matchPathFast(path, rule)`:
  - `exact`: `path === pathExact`
  - `prefix`: `path === pathPrefix || path.startsWith(pathPrefix + "/")`
  - fallback: use `pathRegex`
- Update `pickConfigWithId` to use fast matchers per rule while preserving original order.
- Update `buildEvalContext` to accept `whenNeeds` and only parse cookies if `whenNeeds.cookie` (keep other fields unchanged).

**Step 4: Run tests to verify they pass**

Run: `node --test tests/when-runtime.test.js`
Expected: PASS

Run: `node --test`
Expected: PASS (all suites)

**Step 5: Commit**

```bash
git add pow-config.js tests/when-runtime.test.js
git commit -m "feat: add matcher fast path in pow-config"
```
