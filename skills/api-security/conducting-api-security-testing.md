---
name: conducting-api-security-testing
description: End-to-end security testing workflow for REST, GraphQL, and gRPC APIs covering authentication, authorization, input validation, rate limiting, and business logic vulnerabilities using the OWASP API Security Top 10 as the testing framework.
domain: cybersecurity
subdomain: penetration-testing
tags:
- API-security
- OWASP-API-Top10
- REST
- GraphQL
- authorization-testing
version: 1.0.0
---
# Conducting API Security Testing

## When to Use

- Testing API endpoints for authorization flaws, injection vulnerabilities, and business logic bypasses before release
- Assessing microservices where APIs are the primary communication surface
- Validating that API gateway controls (rate limiting, authentication, input validation) are enforced correctly
- Evaluating third-party API integrations for data exposure or insecure defaults
- Testing GraphQL APIs for introspection disclosure, query complexity abuse, and authorization gaps

**Do not use** against APIs without written authorization. Do not run load or denial-of-service tests unless explicitly in scope.

## Prerequisites

- API documentation (OpenAPI/Swagger, GraphQL schema, or Postman collection), or application access to map the API manually
- Burp Suite Professional configured to intercept API traffic with JSON/XML content-type support
- Postman or Insomnia for organizing and replaying requests across privilege levels
- Valid credentials at multiple privilege levels: unauthenticated, standard user, admin
- Target API base URL and version information

## Workflow

### Step 1: Map the Attack Surface

Build a complete inventory of every API entry point before testing anything.

- **Import API specs**: Load OpenAPI/Swagger docs into Postman or Burp to enumerate all endpoints, methods, parameters, and auth requirements
- **Proxy the frontend**: Run the web or mobile app through Burp while exercising every feature to capture undocumented calls. Export the sitemap as your baseline inventory.
- **GraphQL introspection**: Send the full schema query to discover all types, fields, and relationships:
  ```json
  {"query": "{__schema{types{name,fields{name,args{name,type{name}}}}}}"}
  ```
- **Fuzz for hidden endpoints**: Enumerate alternate API versions (`/api/v1/`, `/api/v2/`, `/internal/`), debug paths (`/debug`, `/health`, `/metrics`), and admin endpoints
- **Identify auth mechanisms**: Document whether the API uses Bearer JWT, API keys, session cookies, OAuth 2.0, or mutual TLS — and whether all endpoints consistently enforce it

### Step 2: Authentication and Token Security

Test each authentication mechanism for weaknesses:

- **JWT**: Decode and inspect every claim (sub, exp, iss, aud, role). Test for:
  - `alg: none` — strip signature and send unsigned token
  - RS256 → HS256 key confusion — re-sign with the public key as HMAC secret
  - Weak secrets — brute-force with `hashcat -m 16500 token.txt wordlist.txt`
  - Missing or excessively long expiration
  - Privilege escalation by modifying role/permission claims and re-signing
- **OAuth 2.0**: Test for `redirect_uri` manipulation, reuse of authorization codes, token leakage in `Referer` headers, and missing `state` parameter (CSRF)
- **API keys**: Verify keys are validated per-endpoint, revoked keys are immediately rejected, and keys passed in query strings do not appear in server logs or analytics

### Step 3: Authorization — BOLA and BFLA

This is the most impactful category. Test every endpoint individually.

**BOLA (Broken Object Level Authorization / IDOR):**
- For every endpoint returning user-specific data, swap the object ID for another user's:
  - `GET /api/users/123/invoices` → try `GET /api/users/456/invoices`
  - Test numeric IDs, UUIDs, base64-encoded values, and slugs
- Use Burp Autorize: configure it with two sessions (attacker and victim) and replay every captured request automatically

**BFLA (Broken Function Level Authorization):**
- With a low-privilege token, attempt every admin-only operation:
  - `DELETE /api/users/456`
  - `PUT /api/users/456/role`
  - `GET /api/admin/dashboard`
- Test HTTP method switching: if `GET /admin/resource` returns 403, also try `POST`, `PUT`, `PATCH`

**Mass Assignment:**
- Send undocumented fields in request bodies:
  ```json
  {"name": "Test", "role": "admin", "isVerified": true, "creditBalance": 99999}
  ```

### Step 4: Input Validation and Injection

SAST tools catch obvious sinks. Test the non-obvious ones:

- **SQL injection in JSON bodies**: `{"username": "admin' OR 1=1--", "password": "x"}`
- **NoSQL operator injection**: `{"username": {"$ne": ""}, "password": {"$ne": ""}}`
- **SSRF**: Any parameter accepting a URL (webhooks, avatar imports, PDF renderers) — test against `http://169.254.169.254/latest/meta-data/` and `http://127.0.0.1:6379/`
- **GraphQL-specific**: Unbounded query depth, alias-based rate-limit bypass for brute force, field suggestion enumeration
- **XXE**: XML-accepting endpoints — submit external entity declarations
- **Rate limiting**: Send 100+ rapid requests to login, password reset, and OTP endpoints; confirm 429 is returned

### Step 5: Response and Data Exposure Analysis

- **Excess fields**: Compare what the API returns vs. what the UI renders. APIs frequently return internal IDs, role flags, password hashes, or other fields the client never uses.
- **Error verbosity**: Trigger errors with malformed input and invalid tokens. Confirm errors do not expose stack traces, SQL queries, internal hostnames, or framework details.
- **Pagination enumeration**: Increment page parameters to confirm you cannot enumerate all records beyond your authorization scope
- **Debug and introspection endpoints**: Check `/debug`, `/.env`, `/swagger.json`, `/graphql` (introspection in production), `/actuator/env`

## Key Concepts

| Term | Definition |
|------|------------|
| **BOLA** | Broken Object Level Authorization — the server authenticates the user but does not verify they own the object being accessed |
| **BFLA** | Broken Function Level Authorization — the server authenticates the user but does not enforce role restrictions on privileged operations |
| **Mass Assignment** | Binding client-supplied JSON fields to internal model properties without an allowlist, allowing attackers to set fields they should not control |
| **GraphQL Introspection** | A built-in GraphQL feature exposing the full schema; must be disabled in production |
| **JWT** | JSON Web Token — a self-contained, signed token carrying auth claims; security depends entirely on algorithm choice and secret strength |
| **Rate Limiting** | Server-side controls capping requests per time window; absence enables brute force, enumeration, and resource abuse |

## Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | API interception, request replay, scanning; Autorize extension for automated BOLA detection |
| **Postman** | Collection management and multi-role request replay |
| **ffuf** | Endpoint and parameter fuzzing |
| **jwt_tool** | JWT decode, tamper, and attack automation |
| **GraphQL Voyager** | Visual exploration of introspected GraphQL schemas |
| **Nuclei** | Template-based scanning for common API misconfigurations |

## Output Format

```
## Finding: Broken Object Level Authorization — Transaction History

**ID**: API-001
**Severity**: Critical (CVSS 9.1)
**Endpoint**: GET /api/v1/accounts/{accountId}/transactions
**OWASP API**: API1:2023 — Broken Object Level Authorization

**Description**:
The endpoint returns transaction history for the specified account without
verifying the authenticated user owns that account. Any authenticated user
can view any account's full transaction history by substituting the accountId.

**Proof of Concept**:
1. Authenticate as User A (account ID: ACC-10045)
2. GET /api/v1/accounts/ACC-10046/transactions  [Authorization: Bearer <User_A_token>]
3. Response: 200 OK — returns User B's complete transaction history

**Impact**: Exposure of financial transaction history for all customer accounts.

**Remediation**:
  const account = await Account.findById(accountId);
  if (account.userId !== req.user.id) return res.status(403).json({ error: 'Forbidden' });
```
