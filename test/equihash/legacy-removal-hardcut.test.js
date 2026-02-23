import test from "node:test";
import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { join, relative } from "node:path";

const repoRoot = fileURLToPath(new URL("../..", import.meta.url));

const walk = async (dir) => {
  const entries = await readdir(dir, { withFileTypes: true });
  const out = [];
  for (const entry of entries) {
    const abs = join(dir, entry.name);
    if (entry.isDirectory()) {
      out.push(...(await walk(abs)));
      continue;
    }
    out.push(abs);
  }
  return out;
};

const activeRoots = [
  "lib",
  "esm",
  "test",
  "pow-core-1.js",
  "pow-core-2.js",
  "pow-config.js",
  "glue.js",
];

const skipFiles = new Set([
  "test/equihash/legacy-removal-hardcut.test.js",
  "test/protocol-surface-hardcut.test.js",
]);

const isTrackedSourceFile = (repoRelPath) =>
  repoRelPath.endsWith(".js") &&
  !repoRelPath.startsWith("dist/") &&
  !repoRelPath.startsWith("node_modules/") &&
  !skipFiles.has(repoRelPath);

const collectActiveFiles = async () => {
  const files = [];
  for (const root of activeRoots) {
    const abs = join(repoRoot, root);
    const rel = relative(repoRoot, abs);
    if (rel.endsWith(".js")) {
      files.push(abs);
      continue;
    }
    files.push(...(await walk(abs)));
  }
  return files.filter((filePath) => isTrackedSourceFile(relative(repoRoot, filePath)));
};

test("repository hard-cut removes legacy ccr/mhg symbols from active code and tests", async () => {
  const files = await collectActiveFiles();
  const forbidden = ["/__pow/commit", "/__pow/challenge", "/__pow/open", "/__pow/cap", "lib/mhg"];
  const endpointVariants = [
    "/__pow%2fcommit",
    "/__pow%2fchallenge",
    "/__pow%2fopen",
    "/__pow%2fcap",
  ];
  const splitMhgPattern = /["'`]lib["'`]\s*,\s*["'`]mhg["'`]/u;
  const joinMhgPattern = /join\(\s*["'`]lib["'`]\s*,\s*["'`]mhg["'`]/u;

  for (const filePath of files) {
    const relPath = relative(repoRoot, filePath);
    const source = await readFile(filePath, "utf8");
    const compact = source.toLowerCase().replace(/[\s"'`+]/gu, "");
    for (const token of forbidden) {
      assert.equal(
        source.includes(token),
        false,
        `legacy token ${token} still present in ${relPath}`,
      );
      assert.equal(
        compact.includes(token),
        false,
        `legacy token variant ${token} still present in ${relPath}`,
      );
    }
    for (const token of endpointVariants) {
      assert.equal(
        compact.includes(token),
        false,
        `legacy encoded endpoint ${token} still present in ${relPath}`,
      );
    }
    assert.equal(splitMhgPattern.test(source), false, `split mhg token still present in ${relPath}`);
    assert.equal(joinMhgPattern.test(source), false, `join(lib,mhg) token still present in ${relPath}`);
  }
});
