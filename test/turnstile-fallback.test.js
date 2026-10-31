import test from "node:test";
import assert from "node:assert/strict";
import { verifyViaSiteverifyAggregator } from "../lib/pow/siteverify-client.js";

test("empty provider list uses the official Turnstile contract without aggregator credentials", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, init) => {
    calls.push({ url, init });
    return Response.json({ success: true });
  });
  for (const urls of [[], ["", "  "], undefined]) {
    const result = await verifyViaSiteverifyAggregator({
      config: { turncheck: true, SITEVERIFY_URLS: urls, AGGREGATOR_POW_ATOMIC_CONSUME: true },
      payload: {
        token: { turnstile: "token" },
        providers: { turnstile: { secret: "secret" } },
        remoteip: "192.0.2.1",
      },
    });
    assert.equal(result.ok, true);
  }
  assert.equal(calls.length, 3);
  for (const { url, init } of calls) {
    assert.equal(url, "https://challenges.cloudflare.com/turnstile/v0/siteverify");
    assert.equal(init.method, "POST");
    assert.equal(new Headers(init.headers).get("authorization"), null);
    assert.deepEqual(JSON.parse(init.body), {
      secret: "secret", response: "token", remoteip: "192.0.2.1",
    });
  }
});

test("official fallback fails closed for rejection, malformed responses and transport failures", async (t) => {
  const responses = [
    () => Response.json({ success: false, "error-codes": ["timeout-or-duplicate"] }),
    () => Response.json({ success: "true" }),
    () => Response.json(null),
    () => new Response("invalid json"),
    () => Response.json({ success: true }, { status: 500 }),
    () => { throw new Error("network"); },
  ];
  let reply;
  t.mock.method(globalThis, "fetch", () => reply());
  for (reply of responses) {
    const result = await verifyViaSiteverifyAggregator({
      config: { turncheck: true, SITEVERIFY_URLS: [] },
      payload: { token: { turnstile: "token" }, providers: { turnstile: { secret: "secret" } } },
    });
    assert.equal(result.ok, false);
  }
});

test("fallback cannot replace PoW-only consumption or accept missing Turnstile input", async (t) => {
  const fetch = t.mock.method(globalThis, "fetch", () => { throw new Error("unexpected request"); });
  for (const [turncheck, token, secret] of [[false, "", ""], [true, "", "secret"], [true, "token", ""]]) {
    const result = await verifyViaSiteverifyAggregator({
      config: { turncheck, SITEVERIFY_URLS: [], AGGREGATOR_POW_ATOMIC_CONSUME: true },
      payload: { token: { turnstile: token }, providers: { turnstile: { secret } } },
    });
    assert.equal(result.ok, false);
  }
  assert.equal(fetch.mock.callCount(), 0);
});
