---
alwaysApply: false
always_on: false
trigger: security_review
applyTo: "**"
description: Full security review — SAST, SCA, fix validation, and breakability assessment using Snyk MCP
---

# Snyk Full Security Review Skill

Perform a complete security review of this codebase in four sequential phases. Do not skip phases or combine them. Report results after each phase before proceeding.

---

## Phase 1 — Source Code Review (SAST)

Run the Snyk static analysis tool against first-party source code:

```
mcp_snyk_snyk_code_scan
```

For each finding:
- Record: severity, CWE, file path, line number, finding title
- Classify as **True Positive** or **False Positive**
  - False positive criteria: the flagged sink is sanitized/escaped elsewhere in the same call chain; or it is protected by global middleware that the scanner cannot trace
- For true positives: identify the exact fix (escape the value, use parameterized query, etc.)
- For false positives: document the suppression rationale clearly

**Do not suppress a finding without verifying the sanitization path in the actual code.**

---

## Phase 2 — Open Source Assessment (SCA)

Run the Snyk software composition analysis tool:

```
mcp_snyk_snyk_sca_scan
```

For each finding, build a table with these columns:
| Severity | Package | Current Version | Fix Version | CVE / CWE | Direct or Transitive |

Separate direct dependencies (in `dependencies` / `devDependencies` in `package.json`) from transitive ones — they require different fix strategies:
- **Direct**: upgrade the version constraint in `package.json`
- **Transitive**: add an entry to the `overrides` block in `package.json` (npm) or `resolutions` (yarn)

Flag any packages where the scanner reports **no fix available** — these require manual triage (deprecation notice, replacement, or accepted risk).

---

## Phase 3 — Fix Validation (Package Health Check)

For every proposed fix version from Phase 2, validate it using:

```
mcp_snyk_snyk_package_health_check { "package_name": "<name>", "version": "<fix-version>", "package_manager": "npm" }
```

Accept a fix version only if the health check returns:
- ✅ No known vulnerabilities
- ✅ Package is not deprecated
- ✅ The version actually exists (Snyk health check DB can lag for very recently released packages — if it returns "insufficient information", cross-reference with `npm show <package> version` to confirm existence)

**Important caveats:**
- Snyk's health check database has a propagation lag of days to weeks for newly published versions. "Insufficient information" does not mean the version is unsafe — confirm with npm registry directly.
- Never mark a fix version as approved based solely on Snyk returning no CVEs if the package doesn't exist on the registry. Always verify with `npm show <package> version`.
- If the SCA scan recommends a fix version and the health check returns insufficient data, the SCA scan is the authoritative source for the CVE fix — accept it with a note that health data is pending.

Record each result: ✅ Approved / ⚠️ Unverified (explain) / ❌ Rejected (explain).

---

## Phase 4 — Breakability Assessment

Before writing any changes to `package.json`, assess the upgrade risk for each package with a non-patch version change.

### For each package being upgraded:

**Step 1 — Check actual usage in the codebase**
- Search all source files for imports, requires, or API calls to the package
- If the package is not imported anywhere in first-party code (i.e., it is purely transitive), upgrade risk is zero — note this and move on
- If it is imported, identify which APIs are used

**Step 2 — Classify the version change**
- Patch bump (x.y.Z): assume safe unless changelog says otherwise
- Minor bump (x.Y.z): safe in semver-compliant packages; spot-check changelog for deprecations
- Major bump (X.y.z): **requires explicit migration guide review**

**Step 3 — For major version bumps only**
- Fetch the official migration guide (e.g., `https://vite.dev/guide/migration` for Vite)
- Identify all breaking changes
- Cross-reference each breaking change against the APIs found in Step 1
- If any used API is listed as removed or changed, **flag as HIGH RISK and recommend the patch/minor fix target instead**

**Step 4 — Rate the risk**
| Risk | Criteria |
|---|---|
| ✅ Zero | Package not imported, or patch bump only |
| ✅ Low | Minor bump, used APIs unchanged |
| ⚠️ Medium | Minor bump with relevant deprecations, or major bump with no relevant API usage |
| ❌ High | Major bump with breaking changes that affect used APIs |

**Decision rule**: If the SCA scan provides a patch or minor fix target that resolves the CVE, use that. Only recommend a major version bump if it is the only available fix.

---

## Phase 5 — Remediation Plan

Produce a consolidated `package.json` diff showing:
1. Direct dependency version bumps (under `dependencies` / `devDependencies`)
2. New or updated `overrides` entries for transitive dependencies
3. Annotate each change with: CVEs fixed, risk rating

Do not apply changes until the user confirms the plan.

---

## Output Format

After all phases complete, present a final summary table:

| Package | Change | CVEs Fixed | Validated | Breakability | Action |
|---|---|---|---|---|---|
| axios | 1.13.5 → 1.15.0 | CVE-2025-62718, CVE-2026-40175 | ✅ | ✅ Low | Bump direct dep |
| vite | 7.3.1 → 7.3.2 | CVE-2026-39363/64/65 | ⚠️ (npm confirmed) | ✅ Zero (patch) | Bump devDep |
| lodash | transitive → ≥4.18.1 | CVE-2026-4800 | ✅ | ✅ Zero (not imported) | Add override |
| inflight | none available | CWE-772 | N/A | N/A | Accepted risk — deprecated transitive, no CVE |

Then state: **"Ready to apply fixes. Confirm to proceed."**
