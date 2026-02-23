import test from "node:test";
import assert from "node:assert/strict";

import { blake2b } from "../../lib/equihash/blake2b.js";

const hex = (bytes) => Buffer.from(bytes).toString("hex");

test("blake2b vectors: empty and abc", () => {
  const empty = blake2b(new Uint8Array(), 64);
  assert.equal(
    hex(empty),
    "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419"
      + "d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce",
  );

  const abc = blake2b(new TextEncoder().encode("abc"), 64);
  assert.equal(
    hex(abc),
    "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1"
      + "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
  );
});

test("blake2b supports personalization and variable output length", () => {
  const input = new TextEncoder().encode("equihash");
  const personal = new Uint8Array(16);
  personal.set(new TextEncoder().encode("ZcashPoW"));
  const d32 = blake2b(input, 32, { personalization: personal });
  const d64 = blake2b(input, 64, { personalization: personal });

  assert.equal(d32.length, 32);
  assert.equal(d64.length, 64);
  assert.notEqual(hex(d64.slice(0, 32)), hex(d32));
});
