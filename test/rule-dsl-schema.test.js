import test from "node:test";
import assert from "node:assert/strict";

import { validateConfigEntry } from "../lib/rule-engine/schema.js";

test("rejects legacy host string", () => {
  assert.throws(
    () => validateConfigEntry({ host: "example.com", config: {} }),
    /host.*matcher/i,
  );
});

test("rejects legacy path RegExp literal", () => {
  assert.throws(
    () => validateConfigEntry({ host: { eq: "example.com" }, path: /^\/api\//, config: {} }),
    /path.*matcher/i,
  );
});

test("rejects legacy when ua string", () => {
  assert.throws(
    () => validateConfigEntry({ host: { eq: "example.com" }, when: { ua: "bot" }, config: {} }),
    /ua.*matcher/i,
  );
});

test("rejects legacy when path RegExp literal", () => {
  assert.throws(
    () =>
      validateConfigEntry({
        host: { eq: "example.com" },
        when: { path: /^\/private\// },
        config: {},
      }),
    /when\.path.*matcher/i,
  );
});

test("rejects non-string re flags", () => {
  assert.throws(
    () =>
      validateConfigEntry({
        host: { re: "^example\\.com$", flags: true },
        config: {},
      }),
    /host\.flags.*string/i,
  );
});

test("reports full path for nested matcher errors", () => {
  assert.throws(
    () =>
      validateConfigEntry(
        {
          host: { eq: "example.com" },
          when: {
            and: [
              { method: { eq: "GET" } },
              { header: { "x-env": "prod" } },
            ],
          },
          config: {},
        },
        "CONFIG[3]",
      ),
    /CONFIG\[3\]\.when\.and\[1\]\.header\["x-env"\].*matcher/i,
  );
});

test("accepts matcher objects", () => {
  assert.doesNotThrow(() =>
    validateConfigEntry({
      host: { glob: "*.example.com" },
      path: { re: "^/api/", flags: "" },
      when: {
        and: [
          { method: { in: ["GET", "POST"] } },
          { header: { "x-env": { eq: "prod" } } },
        ],
      },
      config: {},
    }),
  );
});
