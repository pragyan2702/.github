---
name: implementing-api-security-posture-management
description: Continuously discover, classify, and risk-score APIs across an organization. Enforces security policies, detects shadow APIs and configuration drift, and produces posture dashboards aligned to NIST CSF.
domain: cybersecurity
subdomain: api-security
tags:
- api-security
- posture-management
- api-discovery
- risk-scoring
- api-governance
- continuous-monitoring
version: 1.0.0
---

# Implementing API Security Posture Management

## Overview

API Security Posture Management (API-SPM) provides continuous visibility into an organization's entire API attack surface — internal, external, partner, and shadow endpoints. Unlike point-in-time penetration tests, API-SPM runs continuously to detect new shadow APIs, configuration drift, policy violations, missing security controls, and sensitive data exposure.

It aggregates signals from DAST, SAST, SCA, and runtime traffic analysis to produce a unified, scored view of API risk across the organization.

## When to Use

- Standing up or maturing an API security governance program
- Needing a real-time inventory of all APIs (including undocumented ones)
- Enforcing consistent security policy across hundreds of microservice APIs
- Demonstrating compliance posture for SOC 2, ISO 27001, or PCI-DSS audits
- Detecting shadow or deprecated APIs before attackers do

## Prerequisites

- API gateway with traffic logging enabled (Kong, AWS API Gateway, Apigee, Envoy)
- OpenAPI specifications for all documented APIs (or a plan to generate them)
- SIEM or log aggregation (Splunk, Elastic) for runtime traffic analysis
- CI/CD pipeline access for shift-left API inventory integration
- Python 3.8+ for posture engine tooling

## Core Components

### 1. API Discovery and Inventory Engine

```python
#!/usr/bin/env python3
"""
API Security Posture Management Engine
Discovers, classifies, and risk-scores all API endpoints continuously.
"""

import json, re, hashlib
from datetime import datetime
from typing import Dict, List, Optional, Set
from dataclasses import dataclass, field
from enum import Enum

class Classification(Enum):
    EXTERNAL   = "external"
    INTERNAL   = "internal"
    PARTNER    = "partner"
    SHADOW     = "shadow"      # discovered but undocumented
    DEPRECATED = "deprecated"

class Risk(Enum):
    CRITICAL = 4
    HIGH     = 3
    MEDIUM   = 2
    LOW      = 1

@dataclass
class Control:
    name:     str
    present:  bool
    required: bool
    severity: Risk
    detail:   str = ""

@dataclass
class Endpoint:
    api_id:           str
    method:           str
    path:             str
    service:          str
    classification:   Classification
    owner:            Optional[str] = None
    documented:       bool = False
    first_seen:       str  = ""
    last_seen:        str  = ""
    controls:         List[Control] = field(default_factory=list)
    risk_score:       float = 0.0
    sensitive_types:  Set[str] = field(default_factory=set)
    compliance_tags:  Set[str] = field(default_factory=set)
    daily_requests:   int = 0

class PostureManager:

    SENSITIVE = {
        "ssn":         re.compile(r'\b\d{3}-\d{2}-\d{4}\b'),
        "credit_card": re.compile(r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b'),
        "email":       re.compile(r'\b[\w.+-]+@[\w-]+\.[a-z]{2,}\b', re.I),
        "jwt":         re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+'),
        "api_key":     re.compile(r'\b[A-Za-z0-9]{32,}\b'),
    }

    def __init__(self):
        self.inventory: Dict[str, Endpoint] = {}

    def _id(self, method: str, path: str, service: str) -> str:
        return hashlib.sha256(f"{service}:{method}:{path}".encode()).hexdigest()[:16]

    def register(self, method: str, path: str, service: str,
                 classification: Classification, documented: bool = False,
                 owner: str = None) -> Endpoint:
        eid = self._id(method, path, service)
        now = datetime.now().isoformat()
        if eid in self.inventory:
            self.inventory[eid].last_seen = now
            return self.inventory[eid]
        ep = Endpoint(api_id=eid, method=method, path=path, service=service,
                      classification=classification, owner=owner,
                      documented=documented, first_seen=now, last_seen=now)
        self.inventory[eid] = ep
        return ep

    def assess_controls(self, ep: Endpoint, traffic: dict) -> List[Control]:
        req_hdrs  = traffic.get("request_headers", {})
        resp_hdrs = traffic.get("response_headers", {})
        controls  = []

        # Authentication
        has_auth = any(h in req_hdrs for h in ["Authorization","X-API-Key","Cookie"])
        controls.append(Control("authentication", has_auth, True, Risk.CRITICAL,
            "" if has_auth else "No authentication mechanism detected"))

        # TLS
        is_https = traffic.get("scheme","").lower() == "https"
        controls.append(Control("tls", is_https, True, Risk.CRITICAL,
            "" if is_https else "Endpoint reachable over plain HTTP"))

        # Rate limiting
        has_rl = any(h.startswith("X-RateLimit") or h == "Retry-After"
                     for h in resp_hdrs)
        controls.append(Control("rate_limiting", has_rl, True, Risk.HIGH,
            "" if has_rl else "No rate-limit headers detected"))

        # CORS
        origin = resp_hdrs.get("Access-Control-Allow-Origin", "")
        strict_cors = bool(origin) and origin != "*"
        controls.append(Control("cors", strict_cors,
            ep.classification == Classification.EXTERNAL,
            Risk.HIGH if origin == "*" else Risk.MEDIUM,
            f"CORS origin: {origin}" if origin else "No CORS headers"))

        # Security headers
        required = ["X-Content-Type-Options","Strict-Transport-Security",
                    "X-Frame-Options","Cache-Control"]
        missing = [h for h in required if h not in resp_hdrs]
        controls.append(Control("security_headers", not missing, True, Risk.MEDIUM,
            f"Missing: {', '.join(missing)}" if missing else "All required headers present"))

        # Input validation
        has_validation = traffic.get("has_schema_validation", False)
        controls.append(Control("input_validation", has_validation, True, Risk.HIGH,
            "" if has_validation else "No schema validation detected in logs"))

        ep.controls = controls
        return controls

    def score(self, ep: Endpoint) -> float:
        raw, max_raw = 0.0, 0.0
        for c in ep.controls:
            w = c.severity.value * 5
            max_raw += w
            if not c.present and c.required:
                raw += w
        multiplier = {
            Classification.EXTERNAL:   1.5,
            Classification.PARTNER:    1.3,
            Classification.SHADOW:     2.0,
            Classification.DEPRECATED: 1.8,
            Classification.INTERNAL:   1.0,
        }.get(ep.classification, 1.0)
        if not ep.documented:
            raw += 10
        raw += len(ep.sensitive_types) * 5
        ep.risk_score = round(min(100, (raw / max_raw * 100 * multiplier)) if max_raw else 0, 1)
        return ep.risk_score

    def posture_report(self) -> dict:
        total = len(self.inventory)
        if not total:
            return {"error": "Inventory empty"}
        dist  = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        cl_ct = {c.value: 0 for c in Classification}
        undoc = missing_auth = missing_tls = 0

        for ep in self.inventory.values():
            self.score(ep)
            s = ep.risk_score
            if s >= 75:   dist["CRITICAL"] += 1
            elif s >= 50: dist["HIGH"]     += 1
            elif s >= 25: dist["MEDIUM"]   += 1
            else:         dist["LOW"]      += 1
            cl_ct[ep.classification.value] += 1
            if not ep.documented: undoc += 1
            for c in ep.controls:
                if c.name == "authentication"    and not c.present: missing_auth += 1
                if c.name == "tls"               and not c.present: missing_tls  += 1

        avg = sum(e.risk_score for e in self.inventory.values()) / total
        return {
            "report_date":        datetime.now().isoformat(),
            "total_apis":         total,
            "average_risk_score": round(avg, 1),
            "risk_distribution":  dist,
            "classification":     cl_ct,
            "undocumented":       undoc,
            "missing_auth":       missing_auth,
            "missing_tls":        missing_tls,
            "top_risks": sorted(
                [{"api_id": e.api_id, "method": e.method, "path": e.path,
                  "service": e.service, "risk_score": e.risk_score,
                  "classification": e.classification.value}
                 for e in self.inventory.values()],
                key=lambda x: x["risk_score"], reverse=True
            )[:20],
        }
```

### 2. Policy Definitions

Codify organization-wide API security requirements as machine-readable policies:

```yaml
# api-security-policies.yaml
policies:

  - name: require-authentication
    description: All external and partner APIs must enforce authentication
    scope: [external, partner]
    control: authentication
    severity: critical
    remediation: "Implement OAuth 2.0, JWT Bearer, or API key authentication"

  - name: enforce-tls
    description: All APIs must be served over HTTPS
    scope: [external, internal, partner]
    control: tls
    severity: critical
    remediation: "Provision TLS certificate; configure HTTP→HTTPS redirect"

  - name: rate-limiting-required
    description: External APIs must return rate-limit headers
    scope: [external]
    control: rate_limiting
    severity: high
    remediation: "Configure rate limiting at API gateway; return X-RateLimit-* headers"

  - name: no-wildcard-cors
    description: CORS must not use wildcard origin on credentialed endpoints
    scope: [external]
    control: cors
    condition: "origin != '*'"
    severity: high
    remediation: "Replace Access-Control-Allow-Origin: * with an explicit allowlist"

  - name: openapi-required
    description: All external and partner APIs must have OpenAPI documentation
    scope: [external, partner]
    check: documented == true
    severity: medium
    remediation: "Generate and publish OpenAPI 3.x specification"

  - name: deprecation-sunset
    description: Deprecated APIs must declare a Sunset date via HTTP header
    scope: [deprecated]
    check: "Sunset header present"
    severity: medium
    remediation: "Add `Sunset: <RFC 7231 date>` header to all deprecated endpoints"
```

### 3. Continuous Monitoring — Key Dashboard Metrics

| Metric | Target | Action if missed |
|--------|--------|-----------------|
| API Discovery Coverage (documented %) | > 95% | Audit gateway logs for undocumented routes |
| Average Risk Score | < 25 | Triage high-scoring endpoints immediately |
| Critical-risk APIs | 0 | Immediate remediation SLA |
| Shadow API Count | 0 | Investigate, document, or decommission |
| Authentication Coverage | 100% | Block deployment until fixed |
| TLS Coverage | 100% | Block deployment until fixed |
| Policy Compliance Rate | > 90% | Weekly compliance sprint |
| Mean Time to Remediate (MTTR) | < 7 days | Escalate to engineering lead |

### 4. CI/CD Integration — Shift-Left API Inventory

Prevent shadow APIs by registering every endpoint at deploy time:

```python
# deploy_hook.py — run as part of your deployment pipeline
import os, requests

POSTURE_API = os.environ["POSTURE_API_URL"]
SERVICE     = os.environ["SERVICE_NAME"]
ENV         = os.environ["DEPLOY_ENV"]   # staging | production

def register_endpoints_from_openapi(spec_path: str):
    import yaml
    with open(spec_path) as f:
        spec = yaml.safe_load(f)
    for path, methods in spec.get("paths", {}).items():
        for method in methods:
            if method.lower() in ("get","post","put","patch","delete"):
                requests.post(f"{POSTURE_API}/register", json={
                    "method":         method.upper(),
                    "path":           path,
                    "service":        SERVICE,
                    "classification": "external" if ENV == "production" else "internal",
                    "documented":     True,
                    "owner":          os.environ.get("TEAM_NAME"),
                })

if __name__ == "__main__":
    register_endpoints_from_openapi("openapi.yaml")
```

## Output Format

```
## API Security Posture Report

Date: 2026-04-23  |  Total APIs: 342  |  Avg Risk Score: 31.4

Risk Distribution:
  CRITICAL: 4   HIGH: 28   MEDIUM: 89   LOW: 221

Top Risks:
  1. POST /api/v1/internal/admin/reset       service=auth-svc     score=92  [SHADOW, no auth, no TLS]
  2. GET  /api/v2/users/export               service=user-svc     score=88  [EXTERNAL, no rate limit]
  3. GET  /api/v1/webhooks/debug             service=notify-svc   score=81  [DEPRECATED, no sunset header]

Policy Violations:
  require-authentication : 4 endpoints
  rate-limiting-required : 12 endpoints
  openapi-required       : 19 endpoints
  no-wildcard-cors       : 3 endpoints

Action Items (this sprint):
  P0 — fix missing auth on 4 shadow endpoints (block deployment)
  P1 — add rate limiting to /api/v2/users/export
  P1 — document 19 undocumented external endpoints
  P2 — replace wildcard CORS on 3 endpoints with explicit allowlists
```
