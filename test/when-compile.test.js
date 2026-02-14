import test from "node:test";
import assert from "node:assert/strict";

import { compileConfigEntry } from "../lib/rule-engine/compile.js";
import { validateConfigEntry } from "../lib/rule-engine/schema.js";

test("validateConfigEntry rejects legacy when values", () => {
  assert.throws(
    () =>
      validateConfigEntry({
        host: { eq: "example.com" },
        when: { ua: "bot" },
        config: {},
      }),
    /matcher object/i,
  );

  assert.throws(
    () =>
      validateConfigEntry({
        host: { eq: "example.com" },
        when: { query: { q: /beta/i } },
        config: {},
      }),
    /matcher object/i,
  );
});

test("validateConfigEntry rejects unknown when fields", () => {
  assert.throws(
    () =>
      validateConfigEntry({
        host: { eq: "example.com" },
        when: { and: [{ country: { eq: "US" }, extra: { eq: "x" } }] },
        config: {},
      }),
    /supported condition field/i,
  );
});

test("compileConfigEntry compiles header/cookie/query matcher IR", () => {
  const entry = compileConfigEntry({
    host: { eq: "example.com" },
    when: {
      and: [
        { header: { "x-role": { glob: "*admin*" } } },
        { cookie: { session: { re: "^s-[0-9]+$", flags: "" } } },
        { query: { tag: { exists: true } } },
      ],
    },
    config: { powcheck: true },
  });

  assert.equal(entry.when.kind, "and");
  assert.equal(entry.when.children[0].field, "header");
  assert.equal(entry.when.children[0].matcher.kind, "glob");
  assert.equal(entry.when.children[1].field, "cookie");
  assert.equal(entry.when.children[1].matcher.kind, "re");
  assert.equal(entry.when.children[2].field, "query");
  assert.equal(entry.when.children[2].matcher.kind, "exists");

  assert.deepEqual(entry.whenNeeds, {
    header: true,
    cookie: true,
    query: true,
  });
});
