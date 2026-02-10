import { execFile } from "node:child_process";
import { rm, mkdir, stat } from "node:fs/promises";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);
const repoRoot = fileURLToPath(new URL("..", import.meta.url));
const distDir = join(repoRoot, "dist");
const lockDir = join(repoRoot, ".test-build-lock");
const lockWaitMs = 25;
const lockTimeoutMs = 30_000;
const staleLockMs = 2 * 60 * 1000;

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function acquireBuildLock() {
  const start = Date.now();
  while (true) {
    try {
      await mkdir(lockDir);
      return;
    } catch (error) {
      if (!error || error.code !== "EEXIST") throw error;
      try {
        const lockInfo = await stat(lockDir);
        if (Date.now() - lockInfo.mtimeMs >= staleLockMs) {
          await rm(lockDir, { recursive: true, force: true });
          continue;
        }
      } catch (statError) {
        if (!statError || statError.code !== "ENOENT") throw statError;
      }
      if (Date.now() - start >= lockTimeoutMs) {
        throw new Error(`timed out waiting for build lock: ${lockDir}`);
      }
      await sleep(lockWaitMs);
    }
  }
}

async function withBuildLock(fn) {
  await acquireBuildLock();
  try {
    return await fn();
  } finally {
    await rm(lockDir, { recursive: true, force: true });
  }
}

export async function runBuild({ cleanDist = false } = {}) {
  return withBuildLock(async () => {
    if (cleanDist) {
      await rm(distDir, { recursive: true, force: true });
    }
    return execFileAsync(process.execPath, ["build.mjs"], { cwd: repoRoot });
  });
}

export { repoRoot, distDir };
