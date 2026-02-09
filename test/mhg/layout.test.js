import test from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";

test("mhg core modules exist", () => {
  assert.equal(existsSync("lib/mhg/graph.js"), true);
  assert.equal(existsSync("lib/mhg/mix-aes.js"), true);
});
