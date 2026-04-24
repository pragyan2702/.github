---
name: performing-api-security-testing-with-postman
description: Builds Postman collections for structured OWASP API Top 10 security testing — multi-role environments, automated test scripts, Newman CI/CD integration, and GitHub Actions pipeline configuration.
domain: cybersecurity
subdomain: api-security
tags:
- api-security
- postman
- owasp
- automated-testing
- ci-cd
version: 1.0.0
---
# Performing API Security Testing with Postman

## When to Use

- Building repeatable API security test suites covering OWASP API Top 10
- Running automated security regression tests on every PR via Newman
- Testing authentication and authorization across multiple user roles systematically
- Integrating with OWASP ZAP proxy for passive scanning alongside manual testing
- Establishing baseline security assertions for new endpoints before deployment

**Do not use** against production APIs without authorization.

## Prerequisites

- Postman Desktop or web workspace
- OpenAPI/Swagger spec for collection import (or manually built collection)
- Test accounts for at least three roles: unauthenticated, regular user, admin
- Newman CLI: `npm install -g newman newman-reporter-htmlextra`
- OWASP ZAP as local proxy on `localhost:8080` for passive scan integration
- Environment JSON files for each role with base URL, tokens, and test data IDs

## Workflow

### Step 1: Environment Setup

Create one Postman environment file per role. Never hardcode tokens — use a pre-request login script.

```json
// env-regular-user.json
{
  "values": [
    {"key": "base_url",            "value": "https://staging-api.example.com/api/v1"},
    {"key": "user_email",          "value": "regular@test.example.com"},
    {"key": "user_password",       "value": "TestPass123!"},
    {"key": "auth_token",          "value": ""},
    {"key": "user_id",             "value": ""},
    {"key": "other_user_id",       "value": "1002"},
    {"key": "other_user_order_id", "value": "5003"}
  ]
}
```

**Collection-level pre-request script (auto-login):**
```javascript
if (!pm.environment.get("auth_token")) {
    pm.sendRequest({
        url: pm.environment.get("base_url") + "/auth/login",
        method: "POST",
        header: { "Content-Type": "application/json" },
        body: { mode: "raw", raw: JSON.stringify({
            email:    pm.environment.get("user_email"),
            password: pm.environment.get("user_password")
        })}
    }, (err, res) => {
        if (!err && res.code === 200) {
            pm.environment.set("auth_token", res.json().access_token);
            pm.environment.set("user_id",    res.json().user.id);
        }
    });
}
```

### Step 2: BOLA Tests (API1)

```javascript
// Request: GET {{base_url}}/users/{{other_user_id}}
// Auth: Bearer {{auth_token}}

pm.test("BOLA: Cannot read another user's profile", () => {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});

pm.test("BOLA: No PII returned if request succeeds", () => {
    if (pm.response.code === 200) {
        const body = pm.response.json();
        ["email","phone","address","ssn"].forEach(field => {
            pm.expect(body, `Field '${field}' should not be present`).to.not.have.property(field);
        });
        console.error("BOLA VULNERABILITY: other user profile returned");
    }
});

// Request: PATCH {{base_url}}/orders/{{other_user_order_id}}
// Body: {"status":"cancelled"}
pm.test("BOLA: Cannot modify another user's order", () => {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});
```

### Step 3: Authentication Tests (API2)

```javascript
// Request: GET {{base_url}}/users/me  — no Authorization header
pm.test("Auth: Unauthenticated request rejected", () => {
    pm.expect(pm.response.code).to.equal(401);
});

// Request: GET {{base_url}}/users/me  — Authorization: Bearer invalid_token
pm.test("Auth: Invalid token rejected", () => {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});

// Request: POST {{base_url}}/auth/login  — body: {"email":"' OR 1=1--","password":"x"}
pm.test("Auth: SQL injection in login rejected", () => {
    pm.expect(pm.response.code).to.not.equal(200);
    pm.expect(pm.response.text()).to.not.include("token");
});

// Account enumeration — run this twice: once with a valid email, once with a random one
pm.test("Auth: Same error for valid and invalid usernames", () => {
    const stored = pm.environment.get("valid_user_login_response");
    if (stored) {
        pm.expect(pm.response.text()).to.equal(stored);
    } else {
        pm.environment.set("valid_user_login_response", pm.response.text());
    }
});
```

### Step 4: Data Exposure and BFLA Tests (API3, API5)

```javascript
// Request: GET {{base_url}}/users/me
pm.test("Data Exposure: No sensitive fields in response", () => {
    const sensitive = ["password","password_hash","mfa_secret","ssn","credit_card",
                       "api_key","refresh_token","session_id","private_key"];
    const body = pm.response.text().toLowerCase();
    sensitive.forEach(f => pm.expect(body).to.not.include(`"${f}"`));
});

pm.test("Data Exposure: Security headers present", () => {
    pm.expect(pm.response.headers.get("X-Content-Type-Options")).to.equal("nosniff");
    pm.expect(pm.response.headers.has("Strict-Transport-Security")).to.be.true;
});

pm.test("Data Exposure: No server fingerprint headers", () => {
    pm.expect(pm.response.headers.has("X-Powered-By")).to.be.false;
    pm.expect(pm.response.headers.has("Server")).to.be.false;
});

// Request: GET {{base_url}}/admin/users  — regular user token
pm.test("BFLA: Regular user cannot access admin endpoint", () => {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});

// Request: DELETE {{base_url}}/users/{{other_user_id}}  — regular user token
pm.test("BFLA: Regular user cannot delete other users", () => {
    pm.expect(pm.response.code).to.be.oneOf([401, 403]);
});
```

### Step 5: Mass Assignment and Rate Limiting Tests

```javascript
// Request: PUT {{base_url}}/users/me
// Body: {"name":"Test","role":"admin","is_admin":true,"balance":999999}
pm.test("Mass Assignment: Privilege fields ignored", () => {
    if (pm.response.code === 200) {
        const user = pm.response.json();
        pm.expect(user.role).to.not.equal("admin");
        pm.expect(user.is_admin).to.not.equal(true);
        pm.expect(user.balance).to.not.equal(999999);
    }
});

// Rate limiting — run Collection Runner with 100+ iterations
pm.test("Rate Limiting: 429 returned after threshold", () => {
    if (pm.info.iteration > 50 && pm.response.code === 429) {
        pm.expect(pm.response.headers.has("Retry-After")).to.be.true;
    }
});

pm.test("Rate Limiting: Rate limit headers present on normal request", () => {
    const hasHeader = ["X-RateLimit-Limit","RateLimit-Limit","X-Rate-Limit-Limit"]
        .some(h => pm.response.headers.has(h));
    pm.expect(hasHeader).to.be.true;
});
```

### Step 6: Newman CI/CD Integration

```bash
# Run against staging with regular user role
newman run api-security-tests.json \
  --environment env-regular-user.json \
  --reporters cli,htmlextra,junit \
  --reporter-htmlextra-export reports/security.html \
  --reporter-junit-export    reports/security.xml \
  --timeout-request 10000 \
  --delay-request 100 \
  --bail

# Run across all roles
for role in unauthenticated regular_user admin_user; do
  newman run api-security-tests.json \
    --environment "env-${role}.json" \
    --reporters cli,junit \
    --reporter-junit-export "reports/security-${role}.xml"
done
```

**GitHub Actions workflow:**
```yaml
name: API Security Tests
on:
  pull_request:
    paths: ['src/api/**', 'openapi.yaml']

jobs:
  api-security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: '20' }
      - run: npm install -g newman newman-reporter-htmlextra
      - name: Run security tests
        run: |
          newman run tests/postman/api-security.json \
            --environment tests/postman/env-staging.json \
            --reporters cli,htmlextra,junit \
            --reporter-htmlextra-export reports/security.html \
            --reporter-junit-export     reports/security.xml
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: security-test-reports
          path: reports/
```

## Key Concepts

| Term | Definition |
|------|------------|
| **Postman Collection** | Version-controlled group of API requests with embedded test scripts |
| **Newman** | CLI runner for Postman collections — enables headless CI/CD execution |
| **Pre-request Script** | JavaScript executed before each request — used for dynamic token refresh |
| **Test Script** | JavaScript executed after each response — asserts security properties |
| **Collection Runner** | Executes all requests in sequence; supports iteration counts for rate-limit testing |

## Tools

- **Postman** — collection authoring and manual multi-role test execution
- **Newman** — headless collection runner for CI pipelines
- **OWASP ZAP** — passive security proxy; configure as Postman's upstream proxy
- **newman-reporter-htmlextra** — rich HTML reports with full request/response data

## Output Format

```
## API Security Test Report

Collection: API Security Tests v2.3  |  Role: Regular User  |  Env: Staging
Tests passed: 219 / 234   |   Failed: 15

| # | Request | Test | Severity |
|---|---------|------|----------|
| 1 | GET /users/1002      | BOLA: Cannot read another user's profile  | Critical |
| 2 | GET /orders/5003     | BOLA: Cannot read another user's order   | Critical |
| 3 | GET /admin/users     | BFLA: Regular user blocked from admin    | Critical |
| 4 | PUT /users/me        | Mass Assignment: Privilege fields ignored | High    |
| 5 | GET /users/me        | Data Exposure: No sensitive fields       | High     |
| 6 | POST /auth/login     | Auth: Same error for valid/invalid user  | Medium   |

Recommendations:
1. Add object-level ownership check on GET /users/{id} and GET /orders/{id}
2. Add role middleware to GET /admin/users
3. Implement field allowlist on PUT /users/me
4. Remove password_hash from user serializer
5. Standardize login error messages
```
