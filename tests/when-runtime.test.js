import test from "node:test";
import assert from "node:assert/strict";

globalThis.__COMPILED_CONFIG__ = [];
const powConfig = await import("../pow-config.js");
const { evaluateCondition, matchCidr } = powConfig.__test || {};

test("evaluateCondition handles implicit and/or/not", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = {
    ua: "SuperBot/1.0",
    path: "/API",
    method: "GET",
    country: "US",
    asn: "456",
    header: new Headers({ "x-allow": "1" }),
  };
  const condition = {
    country: "US",
    ua: "bot",
    and: [{ path: "/API" }, { method: "GET" }],
    or: [{ asn: "123" }, { asn: "456" }],
    not: { header: { "x-deny": { exists: true } } },
  };

  assert.equal(evaluateCondition(condition, context), true);
  assert.equal(evaluateCondition({ ...condition, ua: "crawler" }, context), false);
});

test("evaluateCondition matches ua as case-insensitive contains", () => {
  assert.equal(typeof evaluateCondition, "function");
  assert.equal(evaluateCondition({ ua: "bot" }, { ua: "MyBoT/2.0" }), true);
  assert.equal(evaluateCondition({ ua: "bot" }, { ua: "browser" }), false);
});

test("evaluateCondition matches path as case-sensitive exact", () => {
  assert.equal(typeof evaluateCondition, "function");
  assert.equal(evaluateCondition({ path: "/API" }, { path: "/API" }), true);
  assert.equal(evaluateCondition({ path: "/API" }, { path: "/api" }), false);
});

test("evaluateCondition returns false for unknown keys", () => {
  assert.equal(typeof evaluateCondition, "function");
  assert.equal(evaluateCondition({ unknown: "value" }, { ua: "bot" }), false);
});

test("matchCidr supports ipv4 and ipv6", () => {
  assert.equal(typeof matchCidr, "function");
  assert.equal(matchCidr("192.168.1.12", "192.168.1.0/24"), true);
  assert.equal(matchCidr("192.168.2.12", "192.168.1.0/24"), false);
  assert.equal(matchCidr("2001:db8::1", "2001:db8::/32"), true);
  assert.equal(matchCidr("2001:dead::1", "2001:db8::/32"), false);
});

test("evaluateCondition rejects invalid not values", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = { ua: "Agent" };
  assert.equal(evaluateCondition({ not: "invalid" }, context), false);
});

test("evaluateCondition treats empty object as match", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = { ua: "Agent" };
  assert.equal(evaluateCondition({}, context), true);
});

test("evaluateCondition handles header/cookie/query exists checks", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = {
    header: new Headers({ "x-flag": "on" }),
    cookie: new Map([
      ["session", "abc"],
      ["mode", "beta"],
    ]),
    query: new URLSearchParams("tag=alpha&tag=beta"),
  };

  assert.equal(evaluateCondition({ header: { "x-flag": { exists: true } } }, context), true);
  assert.equal(evaluateCondition({ header: { missing: { exists: true } } }, context), false);
  assert.equal(evaluateCondition({ cookie: { session: { exists: true } } }, context), true);
  assert.equal(evaluateCondition({ cookie: { missing: { exists: false } } }, context), true);
  assert.equal(evaluateCondition({ query: { tag: { exists: true } } }, context), true);
  assert.equal(evaluateCondition({ query: { missing: { exists: false } } }, context), true);
});

test("evaluateCondition matches header/cookie/query array and regex values", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = {
    header: new Headers({ "x-role": "admin" }),
    cookie: new Map([
      ["session", "abc"],
      ["mode", "beta"],
    ]),
    query: new URLSearchParams("tag=alpha&tag=beta"),
  };

  assert.equal(
    evaluateCondition({ header: { "x-role": ["user", "admin"] } }, context),
    true
  );
  assert.equal(evaluateCondition({ cookie: { mode: /bet/ } }, context), true);
  assert.equal(evaluateCondition({ query: { tag: /beta/ } }, context), true);
  assert.equal(
    evaluateCondition({ query: { tag: ["delta", "beta"] } }, context),
    true
  );
});

test("evaluateCondition matches any query value", () => {
  assert.equal(typeof evaluateCondition, "function");
  const context = {
    query: new URLSearchParams("tag=alpha&tag=beta"),
  };

  assert.equal(evaluateCondition({ query: { tag: "beta" } }, context), true);
  assert.equal(evaluateCondition({ query: { tag: "delta" } }, context), false);
});

test("pickConfigWithId filters configs by when", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");
  const compiled = [
    {
      hostRegex: /example\.com/,
      pathRegex: null,
      when: { query: { tag: "beta" } },
      config: { id: "beta" },
    },
    {
      hostRegex: /example\.com/,
      pathRegex: null,
      when: { query: { tag: "delta" } },
      config: { id: "delta" },
    },
  ];
  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/?tag=alpha&tag=beta", {
      headers: { "user-agent": "TestAgent" },
    });
    const url = new URL(request.url);
    const selected = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.config?.id, "beta");
  } finally {
    restore();
  }
});
