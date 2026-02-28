# Configuration Guide

## Purpose

Use this guide to define request match rules and per-rule `config` values.

## Minimal Working Config

```js
const CONFIG = [
  {
    host: { eq: "example.com" },
    path: { glob: "/api/**" },
    when: {
      and: [
        { method: { in: ["GET", "POST"] } },
        { header: { "x-env": { eq: "prod" } } },
      ],
    },
    config: {
      POW_TOKEN: "replace-me",
      powcheck: true,
      turncheck: true,
      TURNSTILE_SITEKEY: "replace-me",
      TURNSTILE_SECRET: "replace-me",
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
- Matcher values must use matcher object syntax (for example `{ eq: "example.com" }`, not raw strings).

## Matchers and When Conditions

Use matcher objects for `host`, `path`, and `when`.

- Typical matcher operators are `eq`, `in`, and `glob`.
- `when` adds request conditions (for example `method`, `header`, `query`, `cookie`, `ip`).
- Combine conditions with boolean operators such as `and`, `or`, and `not`.
- Keep `when` minimal: add only conditions needed for routing and policy separation.

## Configuration Reference

Runtime-normalized keys, defaults, and requirement conditions.

Maintainer sync-check (optional): before updating the tables below, run this command to print runtime-normalized defaults and confirm docs stay aligned with current behavior.

```bash
node -e "import('./pow-config.js').then(m=>{console.log(JSON.stringify(m.__testNormalizeConfig({}), null, 2))})"
```

### Gate toggles and route binding

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `powcheck` | boolean | `false` | Set explicitly on routes that should require PoW. | Enables PoW gate behavior for matched traffic. |
| `turncheck` | boolean | `false` | Set explicitly on routes that should require Turnstile. | Enables Turnstile verification for matched traffic. |
| `bindPathMode` | string (`none` \| `query` \| `header`) | `none` | Required when `POW_BIND_PATH=true` and path binding should read from request metadata. | Selects how bound path is sourced for PoW binding checks. |
| `bindPathQueryName` | string | `path` | Required when `bindPathMode=query`. | Query param name used to read bound path input. |
| `bindPathHeaderName` | string | `` (empty) | Required when `bindPathMode=header`. | Header name used to read bound path input. |
| `stripBindPathHeader` | boolean | `false` | Optional; only applies when `bindPathMode=header`. | Removes the bind-path header before forwarding when enabled. |

### PoW challenge/verification controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_VERSION` | number | `4` | Never; fixed by runtime. | Protocol version identifier used by the PoW flow. |
| `POW_API_PREFIX` | string | `/__pow` | Never; fixed by runtime. | URL prefix for PoW API endpoints. |
| `POW_DIFFICULTY_BASE` | number | `8192` | Optional; tune only when adjusting challenge cost. | Base challenge difficulty target. |
| `POW_DIFFICULTY_COEFF` | number | `1` | Optional; tune only when adjusting challenge cost. | Coefficient applied to PoW difficulty calculations. |
| `POW_MIN_STEPS` | number | `512` | Optional; tune only when adjusting challenge bounds. | Minimum solve steps accepted for challenges. |
| `POW_MAX_STEPS` | number | `8192` | Optional; tune only when adjusting challenge bounds. | Maximum solve steps accepted for challenges. |
| `POW_HASHCASH_BITS` | number | `0` | Optional; set when adding hashcash requirement. | Extra hashcash bit requirement for PoW challenges. |
| `POW_PAGE_BYTES` | number | `16384` | Optional; tune only when changing solver workload. | Working set size used by PoW computation. |
| `POW_MIX_ROUNDS` | number | `2` | Optional; tune only when changing solver workload. | Number of PoW mixing rounds. |
| `POW_SEGMENT_LEN` | number or range string | `2` | Optional; tune only when changing solver workload. | Segment sizing used by PoW challenge generation. |
| `POW_SAMPLE_RATE` | number | `0.01` | Optional; tune only for sampling strategy changes. | Sampling rate used by PoW generation logic. |
| `POW_OPEN_BATCH` | number | `4` | Optional; tune only when adjusting open/challenge throughput. | Batch size for PoW open handling. |

### PoW API payload contract

These endpoint payload fields are fixed runtime contract and are not config-driven.

| Endpoint | Contract |
| --- | --- |
| `POST /__pow/commit` | Success response body includes `commitToken` (string, non-empty). |
| `POST /__pow/challenge` | Request JSON must include `commitToken` (string, non-empty) from `/__pow/commit`. |
| `POST /__pow/open` | Request JSON must include `commitToken` (string, non-empty) from `/__pow/commit`. |

`/__pow/challenge` and `/__pow/open` read `commitToken` from JSON body only.

### Proof lifecycle controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_COMMIT_TTL_SEC` | number | `120` | Optional; set when changing commit lifetime policy. | Lifetime of commit material before expiry. |
| `POW_MAX_GEN_TIME_SEC` | number | `300` | Optional; set when changing generation timeout policy. | Maximum PoW generation window. |
| `POW_TICKET_TTL_SEC` | number | `600` | Optional; set when changing ticket lifetime policy. | Lifetime of issued tickets. |
| `PROOF_TTL_SEC` | number | `600` | Optional; set when changing proof lifetime policy. | Lifetime of accepted proofs. |
| `PROOF_RENEW_ENABLE` | boolean | `false` | Required only when using proof renewal. | Turns proof renewal on or off. |
| `PROOF_RENEW_MAX` | number | `2` | Required when `PROOF_RENEW_ENABLE=true`. | Max renewal count allowed per proof. |
| `PROOF_RENEW_WINDOW_SEC` | number | `90` | Required when `PROOF_RENEW_ENABLE=true`. | Renewal eligibility window. |
| `PROOF_RENEW_MIN_SEC` | number | `30` | Required when `PROOF_RENEW_ENABLE=true`. | Minimum age before a proof can renew. |

### Atomic transport controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `ATOMIC_CONSUME` | boolean | `false` | Set to `true` only when consume-token flow is needed. | Enables consume-token handling alongside PoW/Turnstile artifacts. |
| `ATOMIC_TURN_QUERY` | string | `__ts` | Optional override; change only when customizing query field names. | Query key for Turnstile token transport. |
| `ATOMIC_TICKET_QUERY` | string | `__tt` | Optional override; change only when customizing query field names. | Query key for PoW ticket transport. |
| `ATOMIC_CONSUME_QUERY` | string | `__ct` | Optional override; change only when customizing query field names. | Query key for consume token transport. |
| `ATOMIC_TURN_HEADER` | string | `x-turnstile` | Optional override; change only when customizing header names. | Header name for Turnstile token transport. |
| `ATOMIC_TICKET_HEADER` | string | `x-ticket` | Optional override; change only when customizing header names. | Header name for PoW ticket transport. |
| `ATOMIC_CONSUME_HEADER` | string | `x-consume` | Optional override; change only when customizing header names. | Header name for consume token transport. |
| `ATOMIC_COOKIE_NAME` | string | `__Secure-pow_a` | Optional override; change only when customizing cookie names. | Cookie name for packaged atomic transport values. |
| `STRIP_ATOMIC_QUERY` | boolean | `true` | Optional; applies when atomic query params are accepted. | Removes atomic query params before forwarding. |
| `STRIP_ATOMIC_HEADERS` | boolean | `true` | Optional; applies when atomic headers are accepted. | Removes atomic headers before forwarding. |

### Internal bypass controls

Bypass activates only when both name and value are set for the chosen channel.

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `INNER_AUTH_QUERY_NAME` | string | `` (empty) | Optional; set only when enabling query-based internal bypass. | Query param name checked for internal bypass. |
| `INNER_AUTH_QUERY_VALUE` | string | `` (empty) | Required when query-based internal bypass is enabled (`INNER_AUTH_QUERY_NAME` set). | Expected query value for internal bypass. |
| `INNER_AUTH_HEADER_NAME` | string | `` (empty) | Optional; set only when enabling header-based internal bypass. | Header name checked for internal bypass. |
| `INNER_AUTH_HEADER_VALUE` | string | `` (empty) | Required when header-based internal bypass is enabled (`INNER_AUTH_HEADER_NAME` set). | Expected header value for internal bypass. |
| `stripInnerAuthQuery` | boolean | `true` | Optional; applies when bypass query credentials are used. | Strips bypass query credentials before forwarding. |
| `stripInnerAuthHeader` | boolean | `true` | Optional; applies when bypass header credentials are used. | Strips bypass header credentials before forwarding. |

### Ticket binding controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_BIND_PATH` | boolean | `false` | Set to `true` when ticket should be path-bound. | Binds PoW tickets to canonical request path. |
| `POW_BIND_IPRANGE` | boolean | `true` | Optional; disable only if IP range binding is not desired. | Binds tickets to client IP prefix. |
| `POW_BIND_COUNTRY` | boolean | `true` | Optional; disable only if country binding is not desired. | Binds tickets to client country code. |
| `POW_BIND_ASN` | boolean | `true` | Optional; disable only if ASN binding is not desired. | Binds tickets to client ASN. |
| `POW_BIND_TLS` | boolean | `true` | Optional; disable only if TLS fingerprint binding is not desired. | Binds tickets to TLS client fingerprint data. |
| `IPV4_PREFIX` | number | `32` | Required when `POW_BIND_IPRANGE=true` for IPv4 traffic. | IPv4 CIDR prefix length used for binding. |
| `IPV6_PREFIX` | number | `128` | Required when `POW_BIND_IPRANGE=true` for IPv6 traffic. | IPv6 CIDR prefix length used for binding. |

### Endpoint/runtime URL controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_ESM_URL` | string (URL) | `https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@6a34eb1/esm/esm.js` | Optional; set when hosting ESM bundle at a custom location. | URL used to load ESM runtime artifact. |
| `POW_GLUE_URL` | string (URL) | `https://cdn.jsdelivr.net/gh/ImoutoHeaven/snippet-posw@6a34eb1/glue.js` | Optional; set when hosting glue script at a custom location. | URL used to load browser glue runtime artifact. |

### Turnstile/siteverify controls

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `TURNSTILE_SITEKEY` | string | `` (empty) | Required when `turncheck=true`. | Site key presented to clients for Turnstile challenges. |
| `SITEVERIFY_URLS` | string[] | `[]` | Required for successful verification flows when `turncheck=true`; also required for aggregator consume verification flows (`AGGREGATOR_POW_ATOMIC_CONSUME=true`). | Ordered provider endpoint list for server-side verification requests. |
| `SITEVERIFY_AUTH_KID` | string | `v1` | Required when `SITEVERIFY_URLS` is non-empty and auth-kid routing is used. | Key identifier attached to siteverify auth material. |
| `AGGREGATOR_POW_ATOMIC_CONSUME` | boolean | `false` | Set to `true` only when aggregator-backed PoW+atomic consume mode is used. | Enables aggregator-specific consume behavior in combined flows. |

### Secrets

| Key | Type | Default | Required when | What it controls |
| --- | --- | --- | --- | --- |
| `POW_TOKEN` | string | `unset (normalizes to undefined if omitted)` | Required for protected routes (`powcheck=true` and/or `turncheck=true`), and for consume flows. | Shared signing/verification secret across PoW pipeline components. |
| `TURNSTILE_SECRET` | string | `` (empty) | Required whenever `turncheck=true`. | Secret used to verify Turnstile tokens. |
| `SITEVERIFY_AUTH_SECRET` | string | `` (empty) | Required when `SITEVERIFY_URLS` is non-empty and provider auth signing is enabled. | Shared auth secret for siteverify provider requests. |

## 8-Path Matrix (High Level)

High-level mode combinations across PoW, Atomic, and Turnstile.

| P | A | T | Typical use | Operator notes |
| --- | --- | --- | --- | --- |
| Off | Off | Off | Public endpoints with no challenge gate. | Use only where abuse protection is not needed. |
| On | Off | Off | PoW-only protection for automated abuse pressure. | Set `powcheck=true` and provide shared `POW_TOKEN`. |
| Off | On | Off | Unprotected pass-through with atomic fields only. | Atomic alone does not gate traffic; add PoW and/or Turnstile for protection. |
| Off | Off | On | Turnstile-only protection for human verification flows. | Set `turncheck=true` and provide Turnstile keys. |
| On | On | Off | PoW with atomic transport handling. | Keep PoW secrets and atomic field names consistent. |
| On | Off | On | PoW + Turnstile checks without atomic transport. | Validate both challenge paths in staging before rollout. |
| Off | On | On | Turnstile flow with atomic token delivery. | Verify key validity and stripping behavior. |
| On | On | On | Full combined mode for high-risk endpoints. | Roll out gradually and monitor failures. |

## Common Misconfigurations

- Missing `POW_TOKEN` with `powcheck=true` and/or `turncheck=true`: set one shared non-placeholder token across the snippet path.
- `turncheck=true` without Turnstile keys: set both `TURNSTILE_SITEKEY` and `TURNSTILE_SECRET` before enabling checks.
- Inconsistent secrets across snippet chain: keep `POW_TOKEN` (and provider auth secrets, when used) identical across services.
- Invalid matcher shapes: matcher fields must use matcher objects (for example `{ eq: "example.com" }`), not raw strings.
- Incorrect rule order with first-match-wins: place specific rules before broad catch-all rules.
