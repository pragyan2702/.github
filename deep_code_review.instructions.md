---
alwaysApply: false
always_on: false
trigger: deep_code_review
applyTo: "**"
description: Deep-dive manual code review for first-party vulnerabilities that SAST tools miss — auth, authz, business logic, data exposure, injection, secrets, and supply-chain attack surface
---

# Deep Code Security Review Skill

Automated SAST tools (Snyk Code, CodeQL, Semgrep) detect known CWE patterns but miss three whole categories of real vulnerabilities:

1. **Business logic flaws** — the code is syntactically safe but semantically broken (authorization bypass, race conditions, state confusion)
2. **Multi-step attack chains** — no single line is vulnerable, but the combination is
3. **Context-dependent issues** — trust boundary confusion, data flowing through unexpected paths

This skill performs a **manual deep-dive review** of first-party code to find these. Use it *after* `snyk_security_review` passes clean, or before a Mythos-level exposure event when you need to be confident your own code doesn't harbor the next CVE.

Perform the review in seven sequential phases. Report findings after each phase.

---

## Phase 0 — Scope & Attack Surface Mapping

Before scanning anything, build a map of what you're reviewing.

1. **List all HTTP entry points** — every route handler, message queue consumer, webhook receiver, CLI entry point, and scheduled job. Produce a table: `Method | Path | Handler | Auth Required? | Input Sources`.
2. **List all external integrations** — databases, third-party APIs, file systems, child processes, OS commands. Produce a table: `Integration | Location | Data Sent | Data Received | Credentials Source`.
3. **List all trust boundaries** — where untrusted input crosses into trusted zones (request body → DB query, query string → file path, header → shell command, etc.).
4. **Identify the authN/authZ model** — where is authentication enforced? Is it middleware-based or per-route? What are the role/permission primitives?

**Output**: a one-page attack surface map. This is the hit list for all subsequent phases.

---

## Phase 1 — Authentication & Session Management

For every authentication-related code path, verify:

| Check | What To Look For |
|---|---|
| Token storage | Tokens in cookies must be `httpOnly` + `secure` + `SameSite=Strict/Lax`. Never in `localStorage` for high-value sessions. |
| Token generation | Cryptographically random (`crypto.randomBytes`, not `Math.random`). Sufficient entropy (≥128 bits). |
| Token validation | Constant-time comparison (`crypto.timingSafeEqual`), not `===` or `==`. |
| Session fixation | New session ID generated on login. Old session invalidated on logout. |
| Password handling | bcrypt/scrypt/argon2 with appropriate cost factor. Never MD5/SHA-1/SHA-256 of passwords. |
| Credential logging | No passwords, tokens, API keys, or secrets in `console.log`, `logger.info`, error messages, or stack traces. |
| Brute-force protection | Rate limiting on login, password reset, MFA verification, and token refresh endpoints. |
| MFA flows | Verification code stored with short TTL. Cannot be replayed. Cannot be bypassed by repeating the first-factor auth. |
| Password reset | Reset tokens are single-use, short-TTL, invalidate on use, and tied to the account (not guessable). |
| Remember-me | Separate long-lived token, revocable server-side, doesn't grant sensitive operations without re-auth. |

**Prompt for each finding**: "Where is this authenticated? What prevents an attacker from reaching this code path without credentials? What happens if the session token is replayed, tampered, or forged?"

---

## Phase 2 — Authorization (Access Control)

This is where most real-world breaches happen. Check every endpoint individually:

| Check | What To Look For |
|---|---|
| IDOR | Does the handler verify the resource belongs to the requesting user? `/api/orders/:id` must confirm `order.userId === req.user.id`, not just that the user is authenticated. |
| Broken Function Level Authorization | Admin routes gated only by a hidden menu item, not by a server-side role check. |
| Mass Assignment | User can POST arbitrary fields including `isAdmin`, `role`, `userId`. Check every object-assignment from request body. |
| Missing scope checks | Service accounts, API tokens, and OAuth scopes are validated, not just presence. |
| Tenant isolation | In multi-tenant apps, every query filters by `tenantId`/`orgId`. A single missing filter = total data breach. |
| Cross-user data leakage | List endpoints filter to `userId: req.user.id`. Aggregate endpoints don't leak counts across tenants. |
| File path authorization | `/api/files/:path` — attacker cannot read other users' files via path manipulation. |
| GraphQL/batch endpoints | Every resolver/batch item authorized individually, not at the batch level. |

**Manual technique**: Pick 5 random authenticated endpoints. For each, ask: "If I send this request with a *valid* session belonging to User A, but with ID parameters pointing at User B's resources, what happens?" Trace the code path. If the answer is not "it returns 403", it's an IDOR.

---

## Phase 3 — Injection & Input Handling

SAST catches the obvious sinks. This phase catches the subtle ones:

| Injection Type | Non-Obvious Sinks to Check |
|---|---|
| SQL/NoSQL | Dynamic `ORDER BY`, `LIMIT`, `OFFSET`, or table/column names (parameterized queries don't protect these). Raw `$where` in MongoDB. Aggregation pipelines built from user input. |
| Command injection | `child_process.exec()` with any user input. `spawn()` with `shell: true`. Git commands assembled by string concat. |
| SSRF | `axios.get(req.body.url)`, image/avatar fetchers, webhook senders, PDF renderers, URL preview generators. Check for allowlist/blocklist of internal IPs (`169.254.169.254`, `127.0.0.1`, `::1`, `10.0.0.0/8`). |
| Template injection | Any template engine (Handlebars, EJS, Pug, Mustache) rendering user input as the *template* rather than as *data*. |
| Log injection | User input in log messages containing `\n`, `\r` allowing forged log entries. |
| Prototype pollution | `Object.assign(target, req.body)`, `_.merge(config, userInput)`, recursive merge functions without key allowlisting. |
| Regex DoS (ReDoS) | User-controlled regex patterns, or user input matched against regexes with nested quantifiers `(a+)+`, `(a\|b)*c`. |
| XXE | XML parsers without `noent: false` and external entity disabling. |
| Server-side template/SSR | Any HTML built from user input on the server that doesn't use proper escaping. |
| Header injection | `res.setHeader(name, value)` where value comes from user input — `\r\n` enables response splitting. |
| CRLF in URLs | Redirects built from user input without validation. |

**Manual technique**: Grep the codebase for these sinks: `exec(`, `execSync(`, `eval(`, `Function(`, `vm.run`, `child_process`, `child_process.spawn.*shell`, `res.redirect(`, `res.setHeader(`, `new Function(`, `require(`. For each hit, trace inputs backward. If any path reaches `req.body`, `req.query`, `req.params`, `req.headers` without explicit sanitization, flag it.

---

## Phase 4 — Data Exposure & Secrets

| Check | What To Look For |
|---|---|
| Hardcoded secrets | API keys, passwords, tokens, private keys in source. Check config files, test fixtures, git history (`git log -p -S"api_key"`). |
| Secrets in logs | Stack traces, request logs, debug output containing auth headers, tokens, PII. |
| Error verbosity | Production error responses leaking stack traces, SQL errors, file paths, internal hostnames. |
| Sensitive data in URLs | Tokens or PII in query strings (logged by web servers, proxies, browser history). |
| Response field leakage | API serializers returning fields the client shouldn't see (password hashes, internal IDs, soft-delete flags, admin notes). |
| CORS misconfiguration | `Access-Control-Allow-Origin: *` with `Allow-Credentials: true`. Reflected `Origin` header without allowlist. |
| `X-Powered-By` / version headers | Disclosure of framework versions. |
| Source maps in production | `.map` files exposing original source. |
| Debug endpoints | `/debug`, `/admin`, `/metrics`, `/.env`, `/.git`, `/health` exposing internal state. |
| Timing attacks | Token/password comparisons not using constant-time. User existence probes via different response times on login. |
| Memory exposure | `Buffer.allocUnsafe()` without full overwrite. Uninitialized memory returned to clients. |

**Manual technique**: Run `git log -p` and search for the strings `password`, `token`, `secret`, `api_key`, `-----BEGIN`. Run the full app with a proxy (Burp/mitmproxy) and inspect every response for extra fields the UI doesn't use.

---

## Phase 5 — Business Logic & State

Automated tools cannot find these. A human must:

| Check | Examples |
|---|---|
| Race conditions / TOCTOU | `if (user.balance >= amount) { user.balance -= amount }` — two concurrent requests each pass the check. Use DB-level atomic operations or row locks. |
| Workflow bypass | Can a user skip payment and still get the resource? Can they edit an order after checkout? Can they approve their own request? |
| Negative / integer overflow | User inputs negative quantity, oversized integer. Product of large numbers overflowing. |
| Currency / decimal handling | Using floats for money. Rounding errors exploitable for free items. |
| Rate-limit bypass | Rate limit keyed only on IP but endpoint accepts bearer tokens — authenticated user bypasses. Rate limit keyed on user ID but endpoint is pre-auth. |
| Enumeration | Password-reset flow returning different responses for existing vs. non-existing emails. Registration likewise. |
| Replay attacks | Sensitive actions (payment, password change, transfer) without nonce/CSRF/idempotency key. |
| Concurrent login / session fixation | Two active sessions on one account — intended or not? |
| Privilege persistence | User demoted from admin but existing session still has admin capabilities. |
| Cache poisoning | Cache keyed on URL but response varies by `Cookie` or `Authorization` — leaks one user's response to another. |
| HTTP method confusion | Routes handling `POST` but also reachable via `GET` (data in URL gets logged; CSRF easier). |
| Parameter pollution | `?role=user&role=admin` — framework picks one, you check the other. |

**Manual technique**: For each critical workflow (auth, payment, data export, privilege grant), draw the state machine on paper. For each state transition, ask: "What if I'm in state X and send the transition for state Y? What if I send it twice? What if I send it simultaneously?"

---

## Phase 6 — Supply Chain & Build Pipeline

First-party code isn't just source — it's how the source becomes a running artifact.

| Check | What To Look For |
|---|---|
| Dependency confusion | Internal package names that could be claimed on public registries. |
| Lockfile integrity | `package-lock.json` / `yarn.lock` committed. `npm ci` used in CI, not `npm install`. |
| Install scripts | `postinstall` / `preinstall` scripts in dependencies can run arbitrary code. Flag any `install` hooks in top-level deps. |
| Mutable tags | CI uses `actions/checkout@v4` (mutable tag) instead of SHA. A compromised action can exfiltrate secrets. |
| CI secrets scope | Secrets available to PR-triggered workflows from forks. |
| Package publish keys | NPM publish tokens with 2FA disabled. Keys scoped too broadly. |
| Dockerfile `USER` | Containers running as root. Dockerfiles not pinning base image digests. |
| Build artifacts | Source maps, `.env`, `.git`, test files shipped into production images. |
| Typosquatting | Was `react-router` misspelled as `reakt-router`? Check every dependency name against the official spelling. |

**Manual technique**: Read every line of `package.json`, CI workflow YAML files, and Dockerfile. For dependencies, run `npm ls` and skim for names that look suspicious or unfamiliar.

---

## Phase 7 — Cryptography & Protocol

| Check | What To Look For |
|---|---|
| Weak algorithms | MD5, SHA-1, DES, 3DES, RC4, ECB mode. |
| Static IVs / salts | Same IV reused across encryptions. Salts hardcoded. |
| Insecure random | `Math.random()` for security purposes. `Date.now()` as entropy. |
| Missing authentication | Encryption without MAC/AEAD (AES-CBC without HMAC). JWT `alg: none` accepted. |
| JWT pitfalls | Algorithm confusion (RS256 → HS256 using public key as secret). Missing `exp`/`aud`/`iss` checks. Secrets weaker than 256 bits. |
| Key management | Keys in source, config, or env vars with no rotation mechanism. Keys longer-lived than session duration. |
| TLS configuration | `rejectUnauthorized: false` anywhere. Self-signed certs accepted in production. TLS ≤ 1.1. |
| Signature verification | Webhook signatures checked with `==` instead of constant-time. GitHub/Stripe webhook secrets validated? |

---

## Output Format

After completing all phases, produce a findings report with this structure:

```
## Deep Code Review — Findings

### Summary
- Total findings: N
- By severity: X critical, Y high, Z medium, W low, V informational

### Findings

#### FINDING-001 — <Title>
- **Severity**: Critical / High / Medium / Low / Info
- **Phase**: 2 — Authorization
- **Location**: `path/to/file.js:LINE`
- **Category**: IDOR / SSRF / Race Condition / etc.
- **Description**: <One paragraph explaining the flaw>
- **Exploit Scenario**: <Step-by-step how an attacker would exploit this>
- **Proof of Concept**: <curl command, code snippet, or state transition showing the vuln>
- **Impact**: <Data exposed, operations enabled, blast radius>
- **Remediation**: <Exact code changes required>
- **References**: <OWASP, CWE, similar public CVEs>

#### FINDING-002 — ...
```

---

## Hardening Checklist (use as final QA)

Before declaring a component reviewed, confirm:

- [ ] Every route has explicit authentication enforcement verified in the handler (not assumed from middleware)
- [ ] Every route has explicit authorization enforcement that checks resource ownership
- [ ] Every external request (HTTP, DB, shell, file) passes through an allowlist, not a blocklist
- [ ] Every user input that crosses a trust boundary has an explicit validator (Joi, Zod, manual)
- [ ] Every error path returns a generic message to the client; full detail is logged server-side only
- [ ] Every secret is loaded from a secret manager, keychain, or env var — never hardcoded
- [ ] Every cryptographic primitive is named — no custom crypto, no `Math.random`, no unauthenticated encryption
- [ ] Every state-changing endpoint has CSRF protection OR explicit `SameSite` cookie policy OR is bearer-token authenticated
- [ ] Every third-party integration has a documented failure mode and does not fail-open
- [ ] Every deployment artifact has been checked for accidental inclusion of source maps, `.env`, `.git`, test fixtures

---

## When to Use This Skill

| Trigger | Use? |
|---|---|
| Before a major release or compliance audit | ✅ Yes |
| After a publicly-disclosed vulnerability class affects peers | ✅ Yes (focus the phases on the affected category) |
| Mythos-level threat preparation | ✅ Yes — full seven-phase review |
| Routine SAST clean result | ❌ No — `snyk_security_review` is sufficient |
| Pre-merge code review for a small PR | ❌ No — too heavy; apply relevant phases selectively |

This skill is **complementary to, not a replacement for**, `snyk_security_review`. Run Snyk first. Fix what it finds. Then run this to find what it missed.
