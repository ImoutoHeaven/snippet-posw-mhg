# Configuration Guide

## Purpose

Use this guide to define request match rules and per-rule `config` values.

## Minimal Working Config

```js
const CONFIG = [
  {
    host: { eq: "example.com" },
    path: { glob: "/api/**" },
    config: {
      POW_TOKEN: "replace-me",
      powcheck: true,
    },
  },
];
```

## Rule Shape

`CONFIG[]` is an ordered array of rule objects.

- `host` is required on every rule.
- `path` is optional.
- `when` is optional.
- Rule order matters: first match wins.
- Matcher values use matcher object syntax, for example `{ eq: "example.com" }`.

## Matchers and When Conditions

Use matcher objects for `host`, `path`, and `when`.

- Typical matcher operators are `eq`, `in`, and `glob`.
- `when` adds request conditions (for example `method`, `header`, `query`, `cookie`, `ip`).
- Combine conditions with boolean operators such as `and`, `or`, and `not`.
- Keep `when` focused on conditions that define routing and policy separation.

## Configuration Reference

Runtime-normalized keys, defaults, and requirement conditions.

### Gate toggles and route binding

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `powcheck` | boolean | `false` | Set explicitly on routes that should require PoW. | Enables PoW gate behavior for matched traffic. |
| `turncheck` | boolean | `false` | Set explicitly on routes that should require Turnstile. | Enables Turnstile verification for matched traffic. |
| `bindPathMode` | string (`none` \| `query` \| `header`) | `none` | Required when `POW_BIND_PATH=true` and path binding should read from request metadata. | Selects how bound path is sourced for PoW binding checks. |
| `bindPathQueryName` | string | `path` | Required when `bindPathMode=query`. | Query param name used to read bound path input. |
| `bindPathHeaderName` | string | `` (empty) | Required when `bindPathMode=header`. | Header name used to read bound path input. |
| `stripBindPathHeader` | boolean | `false` | Applies when `bindPathMode=header`. | Removes the bind-path header before forwarding when enabled. |

### PoW challenge/verification controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_VERSION` | number | `5` | Fixed by runtime. | Protocol version identifier used by the PoW flow. |
| `POW_API_PREFIX` | string | `/__pow` | Fixed by runtime. | URL prefix for PoW API endpoints. |
| `POW_DIFFICULTY_BASE` | number | `8192` | Optional; tune when adjusting challenge cost. | Base challenge difficulty target. |
| `POW_DIFFICULTY_COEFF` | number | `1` | Optional; tune when adjusting challenge cost. | Coefficient applied to PoW difficulty calculations. |
| `POW_MIN_STEPS` | number | `512` | Optional; tune when adjusting challenge bounds. | Minimum solve steps accepted for challenges. |
| `POW_MAX_STEPS` | number | `8192` | Optional; tune when adjusting challenge bounds. | Maximum solve steps accepted for challenges. |
| `POW_PAGE_BYTES` | number | `16384` | Optional; tune when changing solver workload. | Bytes per MHG page used by graph construction. |
| `POW_MIX_ROUNDS` | number | `2` | Optional; tune when changing solver workload. | Number of PoW mixing rounds. |
| `POW_SEGMENT_LEN` | number or range string | `2` | Optional; tune when changing solver workload. | Segment sizing used by PoW challenge generation. |
| `POW_SAMPLE_RATE` | number | `0.01` | Optional; tune for sampling strategy changes. | Sampling rate used to select indices for opening verification. |
| `POW_OPEN_BATCH` | number | `4` | Optional; tune when adjusting open/challenge throughput. | Batch size for PoW open handling. |

At `L=8192` and `POW_SAMPLE_RATE=0.01`, the sampler selects 82 unique
opening indices: anchors `1` and `L`, one random non-anchor index from each of
64 buckets, and 16 additional random indices. When the non-anchor budget is
below the bucket count, coverage uses a shuffled subset. Any budget left after
coverage supplies random extras.

### PoW API payload contract

These endpoint payload fields form the fixed runtime contract.

| Endpoint | Contract |
| --- | --- |
| `POST /__pow/commit` | Success response body includes `commitToken` (string, non-empty). |
| `POST /__pow/challenge` | Request JSON must include `commitToken` (string, non-empty) from `/__pow/commit`. |
| `POST /__pow/open` | Request JSON must include `commitToken` (string, non-empty) from `/__pow/commit`. |

`/__pow/challenge` and `/__pow/open` read `commitToken` from their JSON bodies.

### Proof lifecycle controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_COMMIT_TTL_SEC` | number | `120` | Optional; set when changing commit lifetime policy. | Lifetime of commit material before expiry. |
| `POW_MAX_GEN_TIME_SEC` | number | `300` | Optional; set when changing generation timeout policy. | Maximum PoW generation window. |
| `POW_TICKET_TTL_SEC` | number | `600` | Optional; set when changing ticket lifetime policy. | Lifetime of issued tickets. |
| `PROOF_TTL_SEC` | number | `600` | Optional; set when changing proof lifetime policy. | Lifetime of accepted proofs. |
| `PROOF_RENEW_ENABLE` | boolean | `false` | Required when using proof renewal. | Turns proof renewal on or off. |
| `PROOF_RENEW_MAX` | number | `2` | Required when `PROOF_RENEW_ENABLE=true`. | Max renewal count allowed per proof. |
| `PROOF_RENEW_WINDOW_SEC` | number | `90` | Required when `PROOF_RENEW_ENABLE=true`. | Renewal eligibility window. |
| `PROOF_RENEW_MIN_SEC` | number | `30` | Required when `PROOF_RENEW_ENABLE=true`. | Minimum age before a proof can renew. |

### Atomic transport controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `ATOMIC_CONSUME` | boolean | `false` | Set to `true` for eligible atomic authorization at the business request. | Enables atomic PoW/Turnstile transport and consumption. |
| `ATOMIC_TURN_QUERY` | string | `__ts` | Optional override for custom query field names. | Query key for Turnstile token transport. |
| `ATOMIC_TICKET_QUERY` | string | `__tt` | Optional override for custom query field names. | Query key for PoW ticket transport. |
| `ATOMIC_CONSUME_QUERY` | string | `__ct` | Optional override for custom query field names. | Query key for consume token transport. |
| `ATOMIC_TURN_HEADER` | string | `x-turnstile` | Optional override for custom header names. | Header name for Turnstile token transport. |
| `ATOMIC_TICKET_HEADER` | string | `x-ticket` | Optional override for custom header names. | Header name for PoW ticket transport. |
| `ATOMIC_CONSUME_HEADER` | string | `x-consume` | Optional override for custom header names. | Header name for consume token transport. |
| `ATOMIC_COOKIE_NAME` | string | `__Secure-pow_a` | Optional override for custom cookie names. | Cookie name for packaged atomic transport values. |
| `STRIP_ATOMIC_QUERY` | boolean | `true` | Optional; applies when atomic query params are accepted. | Removes atomic query params before forwarding. |
| `STRIP_ATOMIC_HEADERS` | boolean | `true` | Optional; applies when atomic headers are accepted. | Removes atomic headers before forwarding. |

### Internal bypass controls

Bypass activates when both name and value are set for the chosen channel.

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `INNER_AUTH_QUERY_NAME` | string | `` (empty) | Optional; set when enabling query-based internal bypass. | Query param name checked for internal bypass. |
| `INNER_AUTH_QUERY_VALUE` | string | `` (empty) | Required when query-based internal bypass is enabled (`INNER_AUTH_QUERY_NAME` set). | Expected query value for internal bypass. |
| `INNER_AUTH_HEADER_NAME` | string | `` (empty) | Optional; set when enabling header-based internal bypass. | Header name checked for internal bypass. |
| `INNER_AUTH_HEADER_VALUE` | string | `` (empty) | Required when header-based internal bypass is enabled (`INNER_AUTH_HEADER_NAME` set). | Expected header value for internal bypass. |
| `stripInnerAuthQuery` | boolean | `true` | Optional; applies when bypass query credentials are used. | Strips bypass query credentials before forwarding. |
| `stripInnerAuthHeader` | boolean | `true` | Optional; applies when bypass header credentials are used. | Strips bypass header credentials before forwarding. |

### Ticket binding controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_BIND_PATH` | boolean | `false` | Set to `true` when ticket should be path-bound. | Binds PoW tickets to canonical request path. |
| `POW_BIND_IPRANGE` | boolean | `true` | Optional; set `false` to use any IP scope. | Binds tickets to client IP prefix. |
| `POW_BIND_COUNTRY` | boolean | `true` | Optional; set `false` to use any country value. | Binds tickets to client country code. |
| `POW_BIND_ASN` | boolean | `true` | Optional; set `false` to use any ASN value. | Binds tickets to client ASN. |
| `POW_BIND_TLS` | boolean | `true` | Optional; set `false` to use any TLS fingerprint. | Binds tickets to TLS client fingerprint data. |
| `IPV4_PREFIX` | number | `32` | Required when `POW_BIND_IPRANGE=true` for IPv4 traffic. | IPv4 CIDR prefix length used for binding. |
| `IPV6_PREFIX` | number | `128` | Required when `POW_BIND_IPRANGE=true` for IPv6 traffic. | IPv6 CIDR prefix length used for binding. |

### Endpoint/runtime URL controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_ESM_URL` | string (URL) | `https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw-mhg@main/esm/esm.js` | Optional; set when hosting ESM bundle at a custom location. | URL used to load ESM runtime artifact. |
| `POW_GLUE_URL` | string (URL) | `https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw-mhg@main/glue.js` | Optional; set when hosting glue script at a custom location. | URL used to load browser glue runtime artifact. |

The default URLs track the repository's `main` branch. Deploy `glue.js`,
`esm/esm.js`, and `esm/mhg-worker.js` from the same published release so the
ESM manifest resolves its sibling Worker. Pin both configurable URLs to the
same immutable published reference, or host the matching asset layout. Custom
self-hosting uses unprotected asset paths ahead of a protected catch-all and
CORS when the asset host differs from the protected origin.

Serve the Worker and JavaScript resources with a JavaScript MIME type.

### Turnstile/siteverify controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `TURNSTILE_SITEKEY` | string | `` (empty) | Required when `turncheck=true`. | Site key presented to clients for Turnstile challenges. |
| `SITEVERIFY_URLS` | string[] | `[]` | Required for PoW-only aggregator consumption. | Ordered provider endpoints; empty with `turncheck=true` uses official Turnstile Siteverify. |
| `SITEVERIFY_AUTH_KID` | string | `v1` | Required when `SITEVERIFY_URLS` is non-empty and auth-kid routing is used. | Key identifier attached to siteverify auth material. |
| `AGGREGATOR_POW_ATOMIC_CONSUME` | boolean | `false` | Set to `true` for aggregator-backed PoW+atomic consume mode. | Enables aggregator-specific consume behavior in combined flows. |

With an empty provider list and `turncheck=true`, the client sends `secret`,
`response`, and optional `remoteip` directly to Cloudflare's official Turnstile
Siteverify endpoint. The official response must have `success=true`, `cdata`
equal to the verified ticket MAC, and `hostname` matching the protected request
hostname (case-insensitive, with no wildcard or suffix matching). Aggregator
authentication is not needed. Token consumption
occurs at proof-cookie issuance in ordinary mode and at the business gate in
atomic mode. Ordinary proof cookies remain reusable. Even with
`AGGREGATOR_POW_ATOMIC_CONSUME=true`, this fallback relies on the proof-bound
Turnstile token for single-use and does not maintain a separate PoW ledger.
PoW-only aggregator consumption without a provider URL fails closed.

### Secrets

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_TOKEN` | string | `unset (normalizes to undefined if omitted)` | Required for protected routes (`powcheck=true` and/or `turncheck=true`), and for consume flows. | Shared signing/verification secret across PoW pipeline components. |
| `TURNSTILE_SECRET` | string | `` (empty) | Required whenever `turncheck=true`. | Secret used to verify Turnstile tokens. |
| `SITEVERIFY_AUTH_SECRET` | string | `` (empty) | Required when `SITEVERIFY_URLS` is non-empty and provider auth signing is enabled. | Shared auth secret for siteverify provider requests. |

## 8-Path Matrix (High Level)

High-level mode combinations across PoW, Atomic, and Turnstile. Atomic flow is
effective when `ATOMIC_CONSUME=true` and (`turncheck=true` or (`powcheck=true`
and `AGGREGATOR_POW_ATOMIC_CONSUME=true`)). Both checks disabled forward the
request. Other combinations use ordinary authorization flow.

| P | A | T | Typical use | Operator notes |
| --- | --- | --- | --- | --- |
| Off | Off | Off | Public pass-through endpoints. | Use for routes with both checks disabled. |
| On | Off | Off | PoW protection for automated abuse pressure. | Set `powcheck=true` and provide shared `POW_TOKEN`. |
| Off | On | Off | Pass-through with atomic fields. | `powcheck=false` and `turncheck=false` select ordinary flow. |
| Off | Off | On | Turnstile protection for human verification flows. | Set `turncheck=true` and provide Turnstile keys. |
| On | On | Off | PoW atomic flow with aggregator consumption. | Set `ATOMIC_CONSUME=true` and `AGGREGATOR_POW_ATOMIC_CONSUME=true`; the pair enables atomic flow. |
| On | Off | On | PoW + Turnstile checks with ordinary transport. | Validate both challenge paths in staging before rollout. |
| Off | On | On | Turnstile flow with atomic token delivery. | Verify key validity and stripping behavior. |
| On | On | On | Full combined mode for high-risk endpoints. | Roll out gradually and monitor failures. |

## Common Misconfigurations

- `powcheck=true` and/or `turncheck=true`: configure one shared non-placeholder `POW_TOKEN` across the snippet path.
- `turncheck=true`: set both `TURNSTILE_SITEKEY` and `TURNSTILE_SECRET` before enabling checks.
- Inconsistent secrets across snippet chain: keep `POW_TOKEN` (and provider auth secrets, when used) identical across services.
- Matcher fields use matcher objects, for example `{ eq: "example.com" }`.
- First-match-wins routing places specific rules before broad catch-all rules.
