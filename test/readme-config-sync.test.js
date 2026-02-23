import test from "node:test";
import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { __testNormalizeConfig } from "../pow-config.js";

const extractSection = (readme, heading, nextHeading) => {
  const start = readme.indexOf(heading);
  if (start === -1) return "";
  const end = readme.indexOf(nextHeading, start + heading.length);
  return end === -1 ? readme.slice(start) : readme.slice(start, end);
};

const extractDocConfigKeys = (readme) => {
  const section = extractSection(readme, "### `config` keys (all supported)", "### `when` conditions");
  const keys = new Set();
  for (const line of section.split(/\r?\n/u)) {
    const match = line.match(/^\|\s*`([^`]+)`\s*\|/u);
    if (match) keys.add(match[1]);
  }
  return keys;
};

test("README config keys stay in sync with runtime normalizeConfig keys", async () => {
  const readme = await readFile("README.md", "utf8");
  const docKeys = extractDocConfigKeys(readme);
  const runtimeKeys = new Set(Object.keys(__testNormalizeConfig({})));

  assert.equal(docKeys.size > 0, true, "README config table must not be empty");
  assert.deepEqual(docKeys, runtimeKeys);
});

test("README is turnstile-only and documents the 8-path matrix", async () => {
  const readme = await readFile("README.md", "utf8");

  assert.doesNotMatch(readme, /reCAPTCHA|recaptcha_v3|recaptchaEnabled|RECAPTCHA_/u);
  assert.match(readme, /8-path/u);
  assert.match(readme, /AGGREGATOR_POW_ATOMIC_CONSUME/u);
});

test("normalizeConfig enforces turnstile-only key surface and atomic consume toggle", () => {
  const cfg = __testNormalizeConfig({
    AGGREGATOR_POW_ATOMIC_CONSUME: "true",
  });

  assert.equal("recaptchaEnabled" in cfg, false);
  assert.equal("RECAPTCHA_PAIRS" in cfg, false);
  assert.equal("RECAPTCHA_ACTION" in cfg, false);
  assert.equal("RECAPTCHA_MIN_SCORE" in cfg, false);
  assert.equal(cfg.AGGREGATOR_POW_ATOMIC_CONSUME, false);

  const cfgTrue = __testNormalizeConfig({ AGGREGATOR_POW_ATOMIC_CONSUME: true });
  assert.equal(cfgTrue.AGGREGATOR_POW_ATOMIC_CONSUME, true);
});

test("README removes stale fields and documents whitepaper knobs", async () => {
  const readme = await readFile("README.md", "utf8");

  assert.equal(readme.includes("POW_SPINE_K"), false);
  assert.equal(readme.includes("POW_FORCE_EDGE_1"), false);
  assert.equal(readme.includes("POW_FORCE_EDGE_LAST"), false);
  assert.equal(readme.includes('digest = SHA256("hashcash|v4|"'), false);
  assert.equal(readme.includes("__Host-pow_commit` (v4)"), false);

  assert.equal(readme.includes("POW_PAGE_BYTES"), false);
  assert.equal(readme.includes("POW_MIX_ROUNDS"), false);
  assert.equal(readme.includes("POW_SEGMENT_LEN"), false);
  assert.equal(readme.includes("POW_SAMPLE_K"), false);
  assert.equal(readme.includes("POW_CHAL_ROUNDS"), false);
  assert.equal(readme.includes("POW_OPEN_BATCH"), false);
  assert.equal(readme.includes("POW_HASHCASH_BITS"), false);
  assert.equal(readme.includes("POW_COMMIT_TTL_SEC"), false);
  assert.equal(readme.includes("POW_MAX_GEN_TIME_SEC"), false);
  assert.equal(readme.includes("POW_COMMIT_COOKIE"), false);
  assert.match(readme, /\| `POW_EQ_N` \| `number` \| `90` \|/u);
  assert.match(readme, /\| `POW_EQ_K` \| `number` \| `5` \|/u);
});

test("README documents siteverify aggregator contract and removes preflight model", async () => {
  const readme = await readFile("README.md", "utf8");

  assert.equal(readme.includes("turnstilePreflight"), false);
  assert.equal(readme.includes("Preflight"), false);
  assert.match(readme, /siteverify aggregator/u);
  assert.match(readme, /auth failure => 404/u);
  assert.match(readme, /fixed 200 with ok\/reason/u);
  assert.match(readme, /rawResponse always returned/u);
  assert.match(readme, /provider network failure maps to provider `httpStatus=502`/u);
  assert.equal(
    readme.includes("Turnstile preflight + forwarding the request to `pow-core-1`"),
    false
  );
});

test("README removes legacy MHG optimization section in hard-cut mode", async () => {
  const readme = await readFile("README.md", "utf8");

  assert.equal(readme.includes("### MHG mix hot-path optimizations"), false);
  assert.equal(readme.includes("pageBytes"), false);
  assert.equal(readme.includes("mix rounds"), false);
});
