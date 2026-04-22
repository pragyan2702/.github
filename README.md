# Vertex Security Expert — GitHub Copilot Agent

A unified security agent for GitHub Copilot that combines:
- **SSDLC Guidance** — reads live from `VertexInc/vertex-knowledge-bases`
- **API Security Testing** — 7 skills from OWASP API Top 10
- **Snyk Scanning** — SAST + SCA + fix validation
- **Deep Code Review** — 7-phase manual security review

---

## Setup (2 steps)

### Step 1 — Copy the agent file

```bash
mkdir -p ~/.copilot/agents
curl -o ~/.copilot/agents/Vertex-security-agent.agent.md \
  https://raw.githubusercontent.com/pragyan2702/.github/main/agents/Vertex-security-agent.agent.md
```

### Step 2 — Configure the GitHub MCP server in VS Code

Open VS Code settings (`Cmd+Shift+P` → "Open User Settings JSON") and add:

```json
"mcp": {
  "servers": {
    "github-mcp-server": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "<your-github-token>"
      }
    }
  }
}
```

To get your GitHub token: go to GitHub → Settings → Developer Settings → Personal Access Tokens → Generate new token (need `repo` scope).

---

## Usage

Open Copilot Chat (`Cmd+Shift+I`) → click the agent picker → select **`vertex-security-expert`**

| What to type | What it does |
|---|---|
| `Walk me through DES-A01 threat modeling` | SSDLC step-by-step guidance |
| `How do I test an API for BOLA?` | API security skill from OWASP |
| `Scan this repo for vulnerabilities` | Snyk SAST + SCA scan |
| `Do a deep security review` | 7-phase manual code review |
| `Full security review of this PR` | Snyk + deep review combined |

---

## Requirements

- VS Code with GitHub Copilot (active subscription)
- Node.js installed (`node --version` to check)
- Access to `VertexInc/vertex-knowledge-bases` on GitHub
