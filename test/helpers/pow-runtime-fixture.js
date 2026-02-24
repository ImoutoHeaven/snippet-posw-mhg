import { mkdtemp, mkdir, readdir, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const REQUIRED_RUNTIME_MODULES = [
  "lib/pow/api-engine.js",
  "lib/pow/inner-auth.js",
  "lib/pow/transit-auth.js",
  "lib/pow/business-gate.js",
  "lib/pow/siteverify-client.js",
  "lib/mhg/constants.js",
  "lib/mhg/graph.js",
  "lib/mhg/hash.js",
  "lib/mhg/merkle.js",
  "lib/mhg/mix-aes.js",
  "lib/mhg/verify.js",
];

const OPTIONAL_RUNTIME_MODULES = [
  "lib/pow/api-core1-front.js",
  "lib/pow/api-protocol-shared.js",
  "lib/pow/auth-primitives.js",
];

export const replaceConfigSecret = (source, secret) =>
  source.replace(/const CONFIG_SECRET = "[^"]*";/u, `const CONFIG_SECRET = "${secret}";`);

const readOptionalText = async (filePath) => {
  try {
    return await readFile(filePath, "utf8");
  } catch (error) {
    if (error && typeof error === "object" && error.code === "ENOENT") return null;
    throw error;
  }
};

const collectJsFiles = async (rootDir, relativeDir, out) => {
  const dirPath = join(rootDir, relativeDir);
  const entries = await readdir(dirPath, { withFileTypes: true });
  for (const entry of entries) {
    const nextRelative = join(relativeDir, entry.name);
    if (entry.isDirectory()) {
      await collectJsFiles(rootDir, nextRelative, out);
      continue;
    }
    if (entry.isFile() && entry.name.endsWith(".js")) out.push(nextRelative);
  }
};

const writeFixtureFile = async ({ repoRoot, tmpDir, relativePath, secret, templateSource }) => {
  const sourcePath = join(repoRoot, relativePath);
  let source = await readFile(sourcePath, "utf8");

  if (relativePath === "pow-core-1.js" || relativePath === "pow-core-2.js") {
    source = replaceConfigSecret(source, secret);
  }
  if (relativePath === "lib/pow/business-gate.js" && templateSource !== null) {
    source = source.replace(/__HTML_TEMPLATE__/gu, JSON.stringify(templateSource));
  }

  const targetPath = join(tmpDir, relativePath);
  await mkdir(dirname(targetPath), { recursive: true });
  await writeFile(targetPath, source);
};

export const createPowRuntimeFixture = async ({
  secret = "config-secret",
  tmpPrefix = "pow-runtime-fixture-",
  copyCoreEntrypoints = true,
  repoRoot = fileURLToPath(new URL("../..", import.meta.url)),
} = {}) => {
  const runtimeEntries = [];
  await collectJsFiles(repoRoot, "lib/pow", runtimeEntries);
  await collectJsFiles(repoRoot, "lib/mhg", runtimeEntries);

  for (const requiredPath of REQUIRED_RUNTIME_MODULES) {
    if (!runtimeEntries.includes(requiredPath)) {
      throw new Error(`missing required runtime module: ${requiredPath}`);
    }
  }

  for (const optionalPath of OPTIONAL_RUNTIME_MODULES) {
    const optionalSource = await readOptionalText(join(repoRoot, optionalPath));
    if (optionalSource !== null && !runtimeEntries.includes(optionalPath)) {
      runtimeEntries.push(optionalPath);
    }
  }

  if (copyCoreEntrypoints) {
    runtimeEntries.push("pow-core-1.js", "pow-core-2.js");
  }

  const templateSource = await readOptionalText(join(repoRoot, "template.html"));
  const tmpDir = await mkdtemp(join(tmpdir(), tmpPrefix));
  const uniqueEntries = Array.from(new Set(runtimeEntries)).sort();

  await Promise.all(
    uniqueEntries.map((relativePath) =>
      writeFixtureFile({ repoRoot, tmpDir, relativePath, secret, templateSource })
    )
  );

  return { tmpDir, repoRoot };
};
