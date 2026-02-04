import test from "node:test";
import assert from "node:assert/strict";
import { writeFile, mkdtemp } from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import { buildCompiledConfig } from "../lib/build-config.js";

const writeTempConfig = async (contents) => {
  const dir = await mkdtemp(path.join(os.tmpdir(), "pow-config-"));
  const filePath = path.join(dir, "pow-config.js");
  await writeFile(filePath, contents, "utf-8");
  return filePath;
};

test("buildCompiledConfig compiles when conditions", async () => {
  const filePath = await writeTempConfig(`
const CONFIG = [
  { pattern: "example.com/api/**", when: { ua: /bot/i }, config: { powcheck: true } },
];
`);

  const compiled = JSON.parse(await buildCompiledConfig(filePath));

  assert.equal(compiled.length, 1);
  const entry = compiled[0];
  assert.equal(entry.when.ua.$re.s, "bot");
  assert.equal(entry.when.ua.$re.f, "i");
  assert.ok(entry.host && entry.host.s.length > 0);
  assert.ok(entry.path && entry.path.s.length > 0);
});

test("buildCompiledConfig rejects invalid when conditions", async () => {
  const filePath = await writeTempConfig(`
 const CONFIG = [
   { pattern: "example.com/api/**", when: { foo: "bar" }, config: { powcheck: true } },
 ];
 `);

  await assert.rejects(() => buildCompiledConfig(filePath), /unknown key/i);
});

test("buildCompiledConfig works without structuredClone", async () => {
  const original = globalThis.structuredClone;
  try {
    globalThis.structuredClone = undefined;
    const filePath = await writeTempConfig(`
const CONFIG = [
  { pattern: "example.com", config: { powcheck: true } },
];
`);

    const compiled = JSON.parse(await buildCompiledConfig(filePath));

    assert.equal(compiled.length, 1);
    assert.ok(compiled[0].host);
  } finally {
    if (original === undefined) {
      delete globalThis.structuredClone;
    } else {
      globalThis.structuredClone = original;
    }
  }
});
