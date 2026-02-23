import test from "node:test";
import assert from "node:assert/strict";

import { handlePowApi } from "../lib/pow/api-engine.js";

const makeInnerCtx = (apiPrefix = "/__pow") => ({
  config: {
    POW_API_PREFIX: apiPrefix,
  },
  powSecret: "pow-secret",
  derived: {
    ipScope: "1.2.3.4/32",
    country: "",
    asn: "",
    tlsFingerprint: "",
  },
  cfgId: 1,
  strategy: {},
});

const callPow = async (path, apiPrefix = "/__pow") => {
  const req = new Request(`https://example.com${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: "{}",
  });
  return handlePowApi(req, new URL(req.url), Math.floor(Date.now() / 1000), makeInnerCtx(apiPrefix));
};

test("pow api only exposes /verify", async () => {
  const verify = await callPow("/__pow/verify");
  assert.equal(verify.status, 403);

  const legacyPaths = [
    "/__pow/commit",
    "/__pow/challenge",
    "/__pow/open",
    "/__pow/cap",
    "/__pow/verify/",
    "/__pow/verifyx",
    "/__pow//verify",
  ];
  for (const path of legacyPaths) {
    const res = await callPow(path);
    assert.equal(res.status, 404);
  }
});

test("pow api hard-cut respects custom POW_API_PREFIX for /verify only", async () => {
  const apiPrefix = "/altpow";
  const verify = await callPow(`${apiPrefix}/verify`, apiPrefix);
  assert.equal(verify.status, 403);

  const legacyPaths = [
    `${apiPrefix}/commit`,
    `${apiPrefix}/challenge`,
    `${apiPrefix}/open`,
    `${apiPrefix}/cap`,
    `${apiPrefix}/verify/`,
    `${apiPrefix}/verifyx`,
    `${apiPrefix}//verify`,
  ];
  for (const path of legacyPaths) {
    const res = await callPow(path, apiPrefix);
    assert.equal(res.status, 404);
  }
});
