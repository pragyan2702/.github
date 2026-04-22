# Vertex Security Expert Agent
### Briefing for Security Champions

---

## What Is It?

A custom AI agent built into **GitHub Copilot** in VS Code that gives every developer a unified security expert — directly in their editor.

Instead of switching between Confluence, Snyk dashboards, and security docs, developers ask the agent and get actionable, Vertex-specific answers in seconds.

---

## What Can It Do?

### 1. SSDLC Guidance
Ask any question about Vertex's security process. The agent reads live from our knowledge base (`VertexInc/vertex-knowledge-bases`) and answers using Vertex-specific policies — not generic advice.

> *"Walk me through threat modeling for my new service"*
> *"What are the mandatory security activities in the Design phase?"*
> *"What does Vertex require for secrets management?"*

### 2. API Security Testing
Built-in skills covering OWASP API Top 10. Guides developers through testing their APIs for the most common and critical vulnerabilities.

> *"How do I test my API for broken object level authorization?"*
> *"Walk me through API authentication weakness testing"*
> *"What tools do I need for API security testing with Postman?"*

### 3. Snyk Security Review
Runs a full automated security scan in 4 phases:
- **SAST** — scans your code for vulnerabilities
- **SCA** — checks all open source dependencies for known CVEs
- **Fix Validation** — verifies each proposed fix is safe to apply
- **Breakability Check** — confirms upgrades won't break your app

> *"Scan this repo for vulnerabilities"*
> *"Check my dependencies for CVEs"*

### 4. Deep Code Review
A 7-phase manual security review that catches what automated scanners miss — auth bypasses, business logic flaws, race conditions, IDOR, and more.

> *"Do a deep security review of the auth logic in this repo"*
> *"Review this PR for security issues before I merge"*

### 5. Always-On Snyk
Automatically scans any new code you write. No trigger needed — it runs silently in the background whenever code is generated.

---

## How It Works

```
You (in Copilot Chat)
        ↓
vertex-security-expert        ← single agent, all capabilities
        ↓
  ┌─────────────────────────────────────────┐
  │ VertexInc/vertex-knowledge-bases        │ ← SSDLC knowledge
  │ mukul975/Anthropic-Cybersecurity-Skills │ ← API security skills
  │ Snyk MCP Server                         │ ← live vulnerability scanning
  │ GitHub MCP Server                       │ ← reads repos in real time
  └─────────────────────────────────────────┘
```

The agent fetches everything **live at the time you ask** — no stale cached data.

---

## Setup (5 minutes)

**Prerequisites:** VS Code + GitHub Copilot subscription + Node.js

### Step 1 — Install the agent file
```bash
mkdir -p ~/.copilot/agents && curl -o ~/.copilot/agents/Vertex-security-agent.agent.md \
  https://raw.githubusercontent.com/pragyan2702/.github/main/agents/Vertex-security-agent.agent.md
```

### Step 2 — Add GitHub MCP server to VS Code settings
Open VS Code → `Cmd+Shift+P` → **Open User Settings (JSON)** → add:

```json
"mcp": {
  "servers": {
    "github-mcp-server": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "<your-github-pat>"
      }
    }
  }
}
```

Get your token: GitHub → Settings → Developer Settings → Personal Access Tokens → `repo` scope.

### Step 3 — Reload VS Code
`Cmd+Shift+P` → **Developer: Reload Window**

---

## How to Use It

Open Copilot Chat (`Cmd+Shift+I`) → click the **agent picker** → select **`vertex-security-expert`**

| Ask this... | Agent does this... |
|---|---|
| SSDLC / process questions | Reads Vertex knowledge base, cites Confluence source |
| API security questions | Applies OWASP API Top 10 skill |
| "Scan this repo" | Runs Snyk SAST + SCA, validates fixes |
| "Deep review" | 7-phase manual security review |
| "Full PR security review" | Snyk scan + deep review combined |

---

## Why This Matters for Security Champions

| Before | After |
|---|---|
| Developer asks you for SSDLC guidance | Agent answers instantly, you focus on complex cases |
| Security reviews happen at the end | Developers self-serve security checks throughout |
| Generic security advice | Vertex-specific policies, every time |
| Separate tools for each task | One agent, all capabilities |

Security Champions can use this agent themselves and recommend it to their teams — lowering the bar for secure-by-design development across Vertex.

---

## What's Next

- **Pentest skills** — adding penetration testing skills from the same library
- **Org-wide rollout** — once validated, add to `VertexInc/.github-private/agents/` so every Vertex developer gets it automatically with zero setup
- **More SSDLC activities** — the knowledge base currently has 1 of 14 activities extracted (DES-A01). More coming.

---

*Agent file: `pragyan2702/.github/agents/Vertex-security-agent.agent.md`*
*Knowledge base: `VertexInc/vertex-knowledge-bases/ssdlc/`*
*Skills library: `mukul975/Anthropic-Cybersecurity-Skills`*
