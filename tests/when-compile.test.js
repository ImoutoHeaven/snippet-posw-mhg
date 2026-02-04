import test from "node:test";
import assert from "node:assert/strict";

import {
  compileWhenCondition,
  validateWhenCondition,
} from "../lib/when-compile.js";

test("compileWhenCondition serializes regex values", () => {
  const input = {
    ua: /bot/i,
    and: [{ country: "CN" }, { path: /\.(css|js)$/ }],
    not: { header: { "x-test": /deny/ } },
  };

  const output = compileWhenCondition(input);

  assert.deepEqual(output, {
    ua: { $re: { s: "bot", f: "i" } },
    and: [
      { country: "CN" },
      { path: { $re: { s: "\\.(css|js)$", f: "" } } },
    ],
    not: { header: { "x-test": { $re: { s: "deny", f: "" } } } },
  });
});

test("validateWhenCondition rejects unknown fields", () => {
  assert.throws(
    () =>
      validateWhenCondition({
        country: "US",
        extra: true,
      }),
    /unknown key/i,
  );
});

test("validateWhenCondition rejects nested unknown keys", () => {
  assert.throws(
    () => validateWhenCondition({ and: [{ country: "US", extra: true }] }),
    /unknown key/i,
  );
});

test("validateWhenCondition rejects invalid types", () => {
  assert.throws(
    () => validateWhenCondition({ and: { country: "US" } }),
    /and/i,
  );
  assert.throws(
    () => validateWhenCondition({ not: /oops/ }),
    /not/i,
  );
  assert.throws(
    () => validateWhenCondition({ tls: "yes" }),
    /tls/i,
  );
  assert.throws(
    () => validateWhenCondition({ country: ["US", 3] }),
    /country/i,
  );
  assert.throws(
    () => validateWhenCondition({ header: { "x-test": { exists: "no" } } }),
    /exists/i,
  );
});

test("validateWhenCondition rejects RegExp outside leaf values", () => {
  assert.throws(() => validateWhenCondition(/top/), /regexp/i);
  assert.throws(() => validateWhenCondition({ and: [/nested/] }), /regexp/i);
});

test("validateWhenCondition accepts leaf RegExp values", () => {
  assert.doesNotThrow(() => validateWhenCondition({ ua: /Firefox/ }));
  assert.doesNotThrow(() =>
    validateWhenCondition({ header: { "user-agent": /bot/i } }),
  );
});

test("validateWhenCondition allows null or undefined", () => {
  assert.doesNotThrow(() => validateWhenCondition(null));
  assert.doesNotThrow(() => validateWhenCondition(undefined));
});

test("validateWhenCondition accepts compiled regex values", () => {
  assert.doesNotThrow(() =>
    validateWhenCondition({ ua: { $re: { s: "bot", f: "i" } } }),
  );
  assert.doesNotThrow(() =>
    validateWhenCondition({ header: { "user-agent": { $re: { s: "bot" } } } }),
  );
  assert.doesNotThrow(() =>
    validateWhenCondition({ query: { q: [{ $re: { s: "abc" } }, "def"] } }),
  );
});
