import test from "node:test";
import assert from "node:assert/strict";

import { compileConfigEntry } from "../lib/rule-engine/compile.js";
import { evaluateWhen } from "../lib/rule-engine/runtime.js";

globalThis.__COMPILED_CONFIG__ = [];
const powConfig = await import("../pow-config.js");

test("matches query multi-value any using text matcher", () => {
  const ctx = { query: new URLSearchParams("tag=alpha&tag=beta") };
  const cond = {
    kind: "atom",
    field: "query",
    key: "tag",
    matcher: { kind: "eq", value: "beta", case: "insensitive" },
  };
  assert.equal(evaluateWhen(cond, ctx), true);
});

test("evaluates and/or/not logic nodes", () => {
  const ctx = {
    method: "GET",
    ua: "SuperBot/1.0",
    header: new Headers({ "x-env": "prod" }),
  };
  const cond = {
    kind: "and",
    children: [
      { kind: "atom", field: "method", matcher: { kind: "in", values: ["GET", "POST"] } },
      {
        kind: "or",
        children: [
          { kind: "atom", field: "ua", matcher: { kind: "glob", pattern: "*crawler*", case: "insensitive" } },
          { kind: "atom", field: "ua", matcher: { kind: "glob", pattern: "*bot*", case: "insensitive" } },
        ],
      },
      {
        kind: "not",
        child: {
          kind: "atom",
          field: "header",
          key: "x-deny",
          matcher: { kind: "exists", value: true },
        },
      },
    ],
  };
  assert.equal(evaluateWhen(cond, ctx), true);
});

test("matches ip with cidr", () => {
  const cond = {
    kind: "atom",
    field: "ip",
    matcher: { kind: "cidr", value: "192.168.1.0/24" },
  };
  assert.equal(evaluateWhen(cond, { ip: "192.168.1.42" }), true);
  assert.equal(evaluateWhen(cond, { ip: "192.168.2.42" }), false);
});

test("supports exists matcher for header/cookie/query", () => {
  const ctx = {
    header: new Headers({ "x-flag": "1" }),
    cookie: new Map([["session", "abc"]]),
    query: new URLSearchParams("tag=alpha"),
  };

  assert.equal(
    evaluateWhen(
      { kind: "atom", field: "header", key: "x-flag", matcher: { kind: "exists", value: true } },
      ctx,
    ),
    true,
  );
  assert.equal(
    evaluateWhen(
      { kind: "atom", field: "cookie", key: "missing", matcher: { kind: "exists", value: false } },
      ctx,
    ),
    true,
  );
  assert.equal(
    evaluateWhen(
      { kind: "atom", field: "query", key: "missing", matcher: { kind: "exists", value: false } },
      ctx,
    ),
    true,
  );
});

test("uses explicit ua/path semantics from IR", () => {
  const uaCond = {
    kind: "atom",
    field: "ua",
    matcher: { kind: "glob", pattern: "*bot*", case: "insensitive" },
  };
  const pathCond = {
    kind: "atom",
    field: "path",
    matcher: { kind: "eq", value: "/API", case: "sensitive" },
  };

  assert.equal(evaluateWhen(uaCond, { ua: "myBoT/2.0" }), true);
  assert.equal(evaluateWhen(pathCond, { path: "/API" }), true);
  assert.equal(evaluateWhen(pathCond, { path: "/api" }), false);
});

test("compiler normalizes ua eq into contains semantics in IR", () => {
  const compiled = compileConfigEntry({
    host: { eq: "example.com" },
    when: { ua: { eq: "bot" } },
    config: {},
  });

  assert.equal(compiled.when.kind, "atom");
  assert.equal(compiled.when.field, "ua");
  assert.deepEqual(compiled.when.matcher, {
    kind: "glob",
    pattern: "*bot*",
    case: "insensitive",
  });
  assert.equal(evaluateWhen(compiled.when, { ua: "SuperBot/1.0" }), true);
});

test("pow-config uses first-match-wins with runtime IR", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");

  const compiled = [
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: null,
      pathType: null,
      when: {
        kind: "atom",
        field: "query",
        key: "tag",
        matcher: { kind: "eq", value: "beta", case: "insensitive" },
      },
      whenNeeds: { query: true },
      config: { id: "first" },
    },
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: null,
      pathType: null,
      when: null,
      config: { id: "second" },
    },
  ];

  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/?tag=beta", {
      headers: { "user-agent": "browser" },
    });
    const url = new URL(request.url);
    const selected = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.cfgId, 0);
    assert.equal(selected?.config?.id, "first");
  } finally {
    restore();
  }
});

test("pow-config keeps whenNeeds lazy cookie parsing behavior", () => {
  const { __test } = powConfig;
  assert.equal(typeof __test?.setCompiledConfigForTest, "function");
  assert.equal(typeof __test?.pickConfigWithId, "function");

  const compiled = [
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: { kind: "eq", value: "/foo", case: "sensitive" },
      pathType: "exact",
      pathExact: "/foo",
      when: {
        kind: "atom",
        field: "ua",
        matcher: { kind: "glob", pattern: "*bot*", case: "insensitive" },
      },
      whenNeeds: { ua: true },
      config: { id: "ua-only" },
    },
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: { kind: "eq", value: "/foo", case: "sensitive" },
      pathType: "exact",
      pathExact: "/foo",
      when: {
        kind: "atom",
        field: "cookie",
        key: "session",
        matcher: { kind: "eq", value: "abc", case: "insensitive" },
      },
      whenNeeds: { cookie: true },
      config: { id: "cookie" },
    },
  ];

  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/foo", {
      headers: { "user-agent": "browser", cookie: "session=abc" },
    });
    const url = new URL(request.url);
    const selected = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    assert.equal(selected?.cfgId, 1);
    assert.equal(selected?.config?.id, "cookie");
  } finally {
    restore();
  }
});

test("evaluateWhen fails closed for malformed logic and atom nodes", () => {
  assert.equal(evaluateWhen({ kind: "unknown" }, {}), false);
  assert.equal(evaluateWhen({ kind: "and", children: {} }, {}), false);
  assert.equal(evaluateWhen({ kind: "or", children: {} }, {}), false);
  assert.equal(evaluateWhen({ kind: "atom", field: "ua" }, { ua: "bot" }), false);
});

test("evaluateWhen not node inverts malformed child result", () => {
  assert.equal(evaluateWhen({ kind: "not", child: { kind: "unknown" } }, {}), true);
});

test("pow-config checks path matcher fallback when metadata is absent", () => {
  const { __test } = powConfig;
  const compiled = [
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: { kind: "eq", value: "/match", case: "sensitive" },
      pathType: null,
      pathRegex: null,
      when: null,
      config: { id: "eq-fallback" },
    },
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: { kind: "glob", pattern: "/api/*", case: "sensitive" },
      pathType: null,
      pathRegex: null,
      when: null,
      config: { id: "glob-fallback" },
    },
  ];

  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const mismatch = new Request("https://example.com/other");
    const mismatchUrl = new URL(mismatch.url);
    const selectedMismatch = __test.pickConfigWithId(
      mismatch,
      mismatchUrl,
      mismatchUrl.hostname,
      mismatchUrl.pathname,
    );
    assert.equal(selectedMismatch, null);

    const matchEq = new Request("https://example.com/match");
    const matchEqUrl = new URL(matchEq.url);
    const selectedEq = __test.pickConfigWithId(matchEq, matchEqUrl, matchEqUrl.hostname, matchEqUrl.pathname);
    assert.equal(selectedEq?.config?.id, "eq-fallback");

    const matchGlob = new Request("https://example.com/api/v1");
    const matchGlobUrl = new URL(matchGlob.url);
    const selectedGlob = __test.pickConfigWithId(
      matchGlob,
      matchGlobUrl,
      matchGlobUrl.hostname,
      matchGlobUrl.pathname,
    );
    assert.equal(selectedGlob?.config?.id, "glob-fallback");
  } finally {
    restore();
  }
});

test("pow-config checks host matcher fallback when metadata is absent", () => {
  const { __test } = powConfig;
  const compiled = [
    {
      host: { kind: "eq", value: "example.com" },
      hostType: null,
      hostRegex: null,
      path: null,
      pathType: null,
      pathRegex: null,
      when: null,
      config: { id: "host-eq-fallback" },
    },
    {
      host: { kind: "glob", pattern: "*.example.net", case: "insensitive" },
      hostType: null,
      hostRegex: null,
      path: null,
      pathType: null,
      pathRegex: null,
      when: null,
      config: { id: "host-glob-fallback" },
    },
  ];

  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const mismatch = new Request("https://other.example.org/");
    const mismatchUrl = new URL(mismatch.url);
    const selectedMismatch = __test.pickConfigWithId(
      mismatch,
      mismatchUrl,
      mismatchUrl.hostname,
      mismatchUrl.pathname,
    );
    assert.equal(selectedMismatch, null);

    const matchEq = new Request("https://example.com/");
    const matchEqUrl = new URL(matchEq.url);
    const selectedEq = __test.pickConfigWithId(matchEq, matchEqUrl, matchEqUrl.hostname, matchEqUrl.pathname);
    assert.equal(selectedEq?.config?.id, "host-eq-fallback");

    const matchGlob = new Request("https://api.example.net/");
    const matchGlobUrl = new URL(matchGlob.url);
    const selectedGlob = __test.pickConfigWithId(
      matchGlob,
      matchGlobUrl,
      matchGlobUrl.hostname,
      matchGlobUrl.pathname,
    );
    assert.equal(selectedGlob?.config?.id, "host-glob-fallback");
  } finally {
    restore();
  }
});

test("pow-config host regex fallback with g flag is stable across repeated picks", () => {
  const { __test } = powConfig;
  const compiled = [
    {
      host: { kind: "re", source: "^api\\.example\\.com$", flags: "g" },
      hostType: null,
      hostRegex: null,
      path: null,
      pathType: null,
      pathRegex: null,
      when: null,
      config: { id: "host-regex-g" },
    },
  ];

  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://api.example.com/");
    const url = new URL(request.url);

    const first = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    const second = __test.pickConfigWithId(request, url, url.hostname, url.pathname);

    assert.equal(first?.config?.id, "host-regex-g");
    assert.equal(second?.config?.id, "host-regex-g");
  } finally {
    restore();
  }
});

test("pow-config path regex fallback with y flag is stable across repeated picks", () => {
  const { __test } = powConfig;
  const compiled = [
    {
      host: { kind: "eq", value: "example.com" },
      hostType: "exact",
      hostExact: "example.com",
      path: { kind: "re", source: "^/api$", flags: "y" },
      pathType: null,
      pathRegex: null,
      when: null,
      config: { id: "path-regex-y" },
    },
  ];

  const restore = __test.setCompiledConfigForTest(compiled);
  try {
    const request = new Request("https://example.com/api");
    const url = new URL(request.url);

    const first = __test.pickConfigWithId(request, url, url.hostname, url.pathname);
    const second = __test.pickConfigWithId(request, url, url.hostname, url.pathname);

    assert.equal(first?.config?.id, "path-regex-y");
    assert.equal(second?.config?.id, "path-regex-y");
  } finally {
    restore();
  }
});

test("malformed regex IR fails closed and does not match", () => {
  const cond = {
    kind: "atom",
    field: "ua",
    matcher: { kind: "re", source: "(", flags: "" },
  };
  assert.equal(evaluateWhen(cond, { ua: "bot" }), false);
});
