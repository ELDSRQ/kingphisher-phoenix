# Dependency Advisory Disposition — 2026-10 (KP-AUD-021 / W0-03)

Audit finding: **KP-AUD-021** (P0, RED) — frozen dependencies (`uv.lock`) contained
current advisory matches. This note records the disposition of every advisory ID
in scope after the remediation upgrade and lock regeneration.

## Remediation summary

| Package   | Old version | New version (locked) | Required floor      | Explicit pin updated |
|-----------|-------------|----------------------|---------------------|----------------------|
| certifi   | 2026.7.22   | 2026.10.23           | >= 2026.10.19       | transitive (lock-only) |
| dnspython | 2.8.0       | 2.9.0                | 2.9.0               | `packages/domain-verification`, `packages/templating` -> `>=2.9.0` |
| urllib3   | 2.7.0       | 2.8.0                | 2.8.0               | transitive (lock-only) |
| pyjwt     | 2.13.0      | 2.15.1               | >= 2.15.0           | `apps/operator-api` -> `>=2.15.0` |

Lock is frozen and hashed (sdist + wheel sha256 preserved by `uv lock`). No
unrelated packages changed; the resolver forced no transitive bumps.

certifi resolved to 2026.10.23 (the latest release at or above the 2026.10.19 fix)
and pyjwt resolved to 2.15.1 (one patch above the 2.15.0 fix floor); both satisfy
and exceed the required fixed versions.

## Reachability context

- **OIDC token verification** (`apps/operator-api/src/kp_operator_api/auth.py`):
  production path is **RS256** via `signing_key.key` fetched from the IdP JWKS
  (`OidcIdP.verify_claims`, line ~449); the dev path is **HS256** with a raw
  shared secret (`DevIdP`). Both call `jwt.decode(...)` with explicit
  `algorithms=[...]`, `audience`, `issuer`, and `options={"require": ["exp","iss","aud"]}`.
- **certifi**: CA trust bundle reachable on every outbound TLS call (httpx to
  Azure Graph / SMTP / IdP JWKS).
- **dnspython**: used by domain-verification (DNS-challenge ownership) and
  templating (SPF pre-flight).
- **urllib3**: transitive HTTP stack (requests/httpx chain) on outbound calls.

## Advisory disposition (21 rows)

| # | Advisory ID | Package | Version (old -> new) | Status | Reachability note |
|---|-------------|---------|----------------------|--------|-------------------|
| 1  | PYSEC-2026-4320 | certifi   | 2026.7.22 -> 2026.10.23 | fixed    | CA bundle; outbound TLS trust (Azure/SMTP/JWKS). Fixed >= 2026.10.19. |
| 2  | PYSEC-2026-4320 | certifi   | 2026.7.22 -> 2026.10.23 | fixed    | Second advisory match-row for same bundle fix; same outbound-TLS reach. |
| 3  | CVE-2026-114605 | dnspython | 2.8.0 -> 2.9.0          | fixed    | DNS-challenge domain verification + SPF pre-flight. Fixed in 2.9.0. |
| 4  | PYSEC-2026-4140 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode (prod RS256 signing_key.key; dev HS256 raw secret). Fixed in 2.14.0. |
| 5  | PYSEC-2026-4141 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.15.0. |
| 6  | PYSEC-2026-4142 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 7  | PYSEC-2026-4143 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 8  | PYSEC-2026-4144 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 9  | PYSEC-2026-4145 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 10 | PYSEC-2026-4146 | pyjwt     | 2.13.0 -> 2.15.1        | **residual** | OIDC decode path. NO listed fix. Owner=operator; review date 2026-10-28. Mitigated by explicit `algorithms`, `audience`, `issuer`, and `require` options; prod uses RS256 JWKS keys only. |
| 11 | PYSEC-2026-4147 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 12 | PYSEC-2026-4148 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 13 | PYSEC-2026-4149 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 14 | PYSEC-2026-4150 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 15 | PYSEC-2026-4151 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 16 | PYSEC-2026-4152 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 17 | PYSEC-2026-4183 | pyjwt     | 2.13.0 -> 2.15.1        | fixed    | OIDC decode path. Fixed in 2.15.0. |
| 18 | GHSA-pxh4-856f-4h89 | pyjwt | 2.13.0 -> 2.15.1      | fixed    | OIDC decode path. Fixed in 2.14.0. |
| 19 | PYSEC-2026-4175 | urllib3   | 2.7.0 -> 2.8.0          | fixed    | Outbound HTTP stack. Fixed in 2.8.0. |
| 20 | PYSEC-2026-4176 | urllib3   | 2.7.0 -> 2.8.0          | fixed    | Outbound HTTP stack. Fixed in 2.8.0. |
| 21 | PYSEC-2026-4177 | urllib3   | 2.7.0 -> 2.8.0          | fixed    | Outbound HTTP stack. Fixed in 2.8.0. |

## Residual

- **PYSEC-2026-4146 (pyjwt)** — no fixed version is listed upstream. Accepted as a
  reviewed residual. **Owner: operator. Review date: 2026-10-28.** Not suppressed
  in scanning; it is recorded here and remains visible. Compensating controls: the
  only `jwt.decode` call sites pin `algorithms` explicitly (RS256 in prod via JWKS
  signing keys, HS256 only on the dev IdP), require `exp`/`iss`/`aud`, and validate
  `audience` and `issuer` — removing the algorithm-confusion / unverified-claim
  surface that these advisories concern.

_No advisory ID was suppressed to obtain a clean scan. Lock remains frozen and hashed._
