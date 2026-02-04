# Pow-config 子规则逻辑增强 Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** 为 `pow-config.js` 增加 when 条件逻辑（AND/OR/NOT、多维度原语、正则、CIDR）并修复隐式 AND 短路、CIDR 缺失、UA 字符串语义、未知字段放行、TLS 语义不一致、Cookie 解析差异等问题。

**Architecture:** 构建期在 `build.mjs` 编译/校验 when（含正则序列化），运行时在 `pow-config.js` 构建上下文并递归求值；匹配逻辑保持“顺序命中即返回”，未知字段默认不匹配，且运行时也做防御性校验。

**Tech Stack:** Cloudflare Snippet (ESM), Node.js build (esbuild/terser), Node 内置 `node --test`

---

### Task 1: when 编译与校验模块 + 单元测试

**Files:**
- Create: `lib/when-compile.js`
- Create: `tests/when-compile.test.js`

**Step 1: 写失败测试**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { compileWhenCondition, validateWhenCondition } from "../lib/when-compile.js";

test("compileWhenCondition 序列化正则", () => {
  const out = compileWhenCondition({ ua: /bot/i, and: [{ country: "CN" }] });
  assert.deepEqual(out, {
    ua: { $re: { s: "bot", f: "i" } },
    and: [{ country: "CN" }],
  });
});

test("validateWhenCondition 拒绝未知字段", () => {
  assert.throws(() => validateWhenCondition({ foo: "bar" }), /unknown|invalid/i);
});
```

**Step 2: 运行测试确认失败**

Run: `node --test tests/when-compile.test.js`
Expected: FAIL（模块不存在或函数未导出）

**Step 3: 实现编译/校验模块**

```js
const ALLOWED_KEYS = new Set([
  "and",
  "or",
  "not",
  "country",
  "asn",
  "ip",
  "method",
  "ua",
  "header",
  "cookie",
  "query",
  "tls",
  "path",
]);

const compileWhenCondition = (when) => {
  if (when === null || when === undefined) return null;
  if (when instanceof RegExp) {
    return { $re: { s: when.source, f: when.flags } };
  }
  if (Array.isArray(when)) return when.map(compileWhenCondition);
  if (typeof when === "object") {
    const out = {};
    for (const [key, val] of Object.entries(when)) {
      out[key] = compileWhenCondition(val);
    }
    return out;
  }
  return when;
};

const validateWhenCondition = (when) => {
  if (when === null || when === undefined) return true;
  if (when instanceof RegExp) return true;
  if (Array.isArray(when)) return when.every(validateWhenCondition);
  if (typeof when !== "object") throw new Error("Invalid when condition");
  const keys = Object.keys(when);
  for (const key of keys) {
    if (!ALLOWED_KEYS.has(key)) throw new Error(`Unknown when key: ${key}`);
  }
  if ("and" in when && !Array.isArray(when.and)) throw new Error("when.and must be array");
  if ("or" in when && !Array.isArray(when.or)) throw new Error("when.or must be array");
  if ("not" in when && (when.not === null || when.not === undefined)) {
    throw new Error("when.not must be condition");
  }
  return keys.every((key) => validateWhenCondition(when[key]));
};

export { compileWhenCondition, validateWhenCondition };
```

**Step 4: 运行测试确认通过**

Run: `node --test tests/when-compile.test.js`
Expected: PASS

**Step 5: 提交**

```bash
git add lib/when-compile.js tests/when-compile.test.js
git commit -m "test: add when compile validation tests"
```

### Task 2: build.mjs 接入 when 编译与校验

**Files:**
- Modify: `build.mjs`

**Step 1: 更新 build.mjs**

- 引入 `compileWhenCondition` / `validateWhenCondition`。
- 在 `compileConfigEntry` 前校验 `entry.when`（非法直接 throw）。
- 在编译结果中加入 `when` 字段。

```js
import { compileWhenCondition, validateWhenCondition } from "./lib/when-compile.js";

const compileConfigEntry = (entry) => {
  const config = (entry && entry.config) || {};
  const parts = splitPattern(entry && entry.pattern);
  const when = entry && "when" in entry ? entry.when : null;
  validateWhenCondition(when);
  const compiledWhen = compileWhenCondition(when);
  // 现有 host/path 编译逻辑...
  return { hostRegex, pathRegex, when: compiledWhen, config };
};

return JSON.stringify(compiled.map((entry) => ({
  host: entry.hostRegex ? { s: entry.hostRegex.source, f: entry.hostRegex.flags } : null,
  path: entry.pathRegex ? { s: entry.pathRegex.source, f: entry.pathRegex.flags } : null,
  when: entry.when || null,
  config: entry.config || {},
})));
```

**Step 2: 运行构建确认通过**

Run: `npm run build`
Expected: build 成功，且 `dist/pow_config_snippet.js` 体积仍低于 32KB

**Step 3: 提交**

```bash
git add build.mjs
git commit -m "feat: compile and validate when conditions"
```

### Task 3: when 运行时求值 + 单元测试

**Files:**
- Modify: `pow-config.js`
- Create: `tests/when-runtime.test.js`

**Step 1: 写失败测试**

```js
import test from "node:test";
import assert from "node:assert/strict";
import { __test } from "../pow-config.js";

const { evaluateCondition, matchCidr } = __test;

test("隐式 AND 与逻辑运算", () => {
  const ctx = {
    country: "CN",
    asn: "4134",
    ip: "192.168.1.9",
    method: "GET",
    ua: "curl/7.81",
    hasTls: true,
    headers: new Headers({ "x-key": "val" }),
    cookies: new Map([["sess", "1"]]),
    query: new URLSearchParams("debug=1"),
    path: "/Admin",
  };

  assert.equal(evaluateCondition(ctx, { country: "CN", asn: "4134" }), true);
  assert.equal(evaluateCondition(ctx, { ua: "curl" }), true);
  assert.equal(evaluateCondition(ctx, { path: "/admin" }), false);
  assert.equal(evaluateCondition(ctx, { not: { country: "US" } }), true);
  assert.equal(evaluateCondition(ctx, { or: [{ country: "US" }, { asn: "4134" }] }), true);
  assert.equal(evaluateCondition(ctx, { foo: "bar" }), false);
});

test("CIDR 匹配 v4/v6", () => {
  assert.equal(matchCidr("10.1.2.3", "10.0.0.0/8"), true);
  assert.equal(matchCidr("2001:db8::1", "2001:db8::/32"), true);
  assert.equal(matchCidr("2001:db9::1", "2001:db8::/32"), false);
});
```

**Step 2: 运行测试确认失败**

Run: `node --test tests/when-runtime.test.js`
Expected: FAIL（`__test` 未导出或实现缺失）

**Step 3: 实现运行时逻辑**

- 为 `__COMPILED_CONFIG__` 增加安全兜底（测试环境下为空数组）。
- 在 `COMPILED_CONFIG` 中反序列化 `when`。
- 新增/修复：`reviveRegex`、`matchValue`（UA 字符串做包含匹配）、`matchObject`、`ipInCidr`、`matchCidr`、`evaluateCondition`（按键遍历避免隐式 AND 短路）、`buildEvalContext`。
- `buildEvalContext` 使用现有 `parseCookieHeader`（Map），`tls` 依据 `cf.tlsClientExtensionsSha1` 与 `cf.tlsClientCiphersSha1` 同时存在。
- `path` 条件使用 `normalizePath` 的结果，字符串匹配改为大小写敏感精确匹配（正则保持原样）。
- `pickConfigWithId` 改为接收 `(request, url, hostname, path)` 并在需要时构建上下文。
- 运行时遇到未知字段时返回 `false`（安全默认）。
- 导出 `__test`（仅供测试使用）。

```js
const RAW_COMPILED_CONFIG =
  typeof __COMPILED_CONFIG__ === "undefined" ? [] : __COMPILED_CONFIG__;

const COMPILED_CONFIG = RAW_COMPILED_CONFIG.map((entry) => ({
  hostRegex: entry.host ? new RegExp(entry.host.s, entry.host.f || "") : null,
  pathRegex: entry.path ? new RegExp(entry.path.s, entry.path.f || "") : null,
  when: reviveWhen(entry.when),
  config: entry.config || {},
}));
```

**Step 4: 运行测试确认通过**

Run: `node --test tests/when-runtime.test.js`
Expected: PASS

**Step 5: 提交**

```bash
git add pow-config.js tests/when-runtime.test.js
git commit -m "feat: add when condition evaluation"
```

### Task 4: README 文档更新

**Files:**
- Modify: `README.md`

**Step 1: 更新文档**

- 增加 `when` 结构与逻辑运算说明。
- 说明字符串匹配语义：
  - `ua`: 不区分大小写的包含匹配。
  - `path`: 大小写敏感的精确匹配。
  - 其它字符串值：不区分大小写的精确匹配。
- 增加 CIDR v4/v6、`header/cookie/query` 的 `exists` 示例。

**Step 2: 提交**

```bash
git add README.md
git commit -m "docs: document when condition syntax"
```

### Task 5: 全量验证

**Files:**
- (none)

**Step 1: 运行全部测试**

Run: `node --test`
Expected: PASS

**Step 2: 运行构建**

Run: `npm run build`
Expected: build 成功，且 `dist/pow_config_snippet.js` 体积仍低于 32KB

**Step 3: 检查工作区状态**

```bash
git status
```
