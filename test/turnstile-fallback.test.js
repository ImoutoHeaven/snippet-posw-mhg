import test from "node:test";
import assert from "node:assert/strict";
import { verifyViaSiteverifyAggregator } from "../lib/pow/siteverify-client.js";

const input = () => ({
  config: { turncheck: true, SITEVERIFY_URLS: [] },
  expectedHostname: "example.com",
  payload: {
    ticketMac: "ticket-mac",
    token: { turnstile: "token" },
    providers: { turnstile: { secret: "secret" } },
    remoteip: "192.0.2.1",
  },
});
const validResponse = { success: true, cdata: "ticket-mac", hostname: "example.com" };

test("empty provider list uses the official Turnstile contract without aggregator credentials", async (t) => {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, init) => {
    calls.push({ url, init });
    return Response.json(validResponse);
  });
  for (const urls of [[], ["", "  "], undefined]) {
    const args = input();
    args.config.SITEVERIFY_URLS = urls;
    args.config.AGGREGATOR_POW_ATOMIC_CONSUME = true;
    const result = await verifyViaSiteverifyAggregator(args);
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

test("official fallback rejects tokens bound to another ticket or hostname", async (t) => {
  let response;
  t.mock.method(globalThis, "fetch", () => Response.json(response));
  const invalid = [
    { cdata: "another-ticket" }, { cdata: undefined }, { cdata: null }, { cdata: 1 },
    { hostname: "other.example.com" }, { hostname: "example.com.attacker.invalid" },
    { hostname: " example.com" }, { hostname: "example.com." },
    { hostname: undefined }, { hostname: null }, { hostname: ["example.com"] },
  ];
  for (const fields of invalid) {
    response = { ...validResponse, ...fields };
    assert.equal((await verifyViaSiteverifyAggregator(input())).ok, false, JSON.stringify(fields));
  }
  response = { ...validResponse, hostname: "EXAMPLE.COM" };
  assert.equal((await verifyViaSiteverifyAggregator(input())).ok, true, "DNS names are case insensitive");
  const args = input();
  args.expectedHostname = "EXAMPLE.COM";
  response = validResponse;
  assert.equal((await verifyViaSiteverifyAggregator(args)).ok, true);
});

test("official fallback fails closed for rejection, malformed responses and transport failures", async (t) => {
  const responses = [
    () => Response.json({ ...validResponse, success: false, "error-codes": ["timeout-or-duplicate"] }),
    () => Response.json({ ...validResponse, success: "true" }),
    () => Response.json(null),
    () => new Response("invalid json"),
    () => Response.json(validResponse, { status: 500 }),
    () => { throw new Error("network"); },
  ];
  let reply;
  t.mock.method(globalThis, "fetch", () => reply());
  for (reply of responses) {
    assert.equal((await verifyViaSiteverifyAggregator(input())).ok, false);
  }
});

test("fallback requires Turnstile credentials and trusted ticket and hostname expectations", async (t) => {
  const fetch = t.mock.method(globalThis, "fetch", () => { throw new Error("unexpected request"); });
  for (const [turncheck, token, secret] of [[false, "", ""], [true, "", "secret"], [true, "token", ""]]) {
    const args = input();
    args.config.turncheck = turncheck;
    args.config.AGGREGATOR_POW_ATOMIC_CONSUME = true;
    args.payload.token.turnstile = token;
    args.payload.providers.turnstile.secret = secret;
    assert.equal((await verifyViaSiteverifyAggregator(args)).ok, false);
  }
  for (const value of [undefined, null, "", 123]) {
    const noHost = input();
    noHost.expectedHostname = value;
    assert.equal((await verifyViaSiteverifyAggregator(noHost)).ok, false);
    const noTicket = input();
    noTicket.payload.ticketMac = value;
    assert.equal((await verifyViaSiteverifyAggregator(noTicket)).ok, false);
  }
  assert.equal(fetch.mock.callCount(), 0);
});
