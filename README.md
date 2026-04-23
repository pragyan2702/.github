# Vertex Security Expert — GitHub Copilot Agent

A unified security agent for GitHub Copilot that combines:
- **SSDLC Guidance** — reads live from `VertexInc/vertex-knowledge-bases`
- **API Security Testing** — 7 skills from OWASP API Top 10 (stored locally in `skills/api-security/`)
- **Snyk Scanning** — SAST + SCA + fix validation
- **Deep Code Review** — 7-phase manual security review

---

## Setup (3 steps)

### Step 1 — Copy the agent file

```bash
mkdir -p ~/.copilot/agents
cp agents/Vertex-security-agent.agent.md ~/.copilot/agents/
```

### Step 2 — Set environment variables for API tokens

**Do not put tokens directly in settings files.** Export them in your shell profile (`~/.zshrc` or `~/.bash_profile`) instead:

```bash
export GITHUB_PERSONAL_ACCESS_TOKEN="ghp_..."   # repo scope
export SNYK_TOKEN="snyk_..."                     # Snyk API token
```

Then reload your shell: `source ~/.zshrc`

To get your **GitHub token**: GitHub → Settings → Developer Settings → Personal Access Tokens → Generate new token (need `repo` scope).

To get your **Snyk token**: Snyk → Account Settings → API Token.

### Step 3 — Configure MCP servers in VS Code

Open VS Code settings (`Cmd+Shift+P` → "Open User Settings JSON") and add:

```json
"mcp": {
  "servers": {
    "github-mcp-server": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-github"],
      "env": {
        "GITHUB_PERSONAL_ACCESS_TOKEN": "${env:GITHUB_PERSONAL_ACCESS_TOKEN}"
      }
    },
    "snyk": {
      "command": "npx",
      "args": ["-y", "snyk-mcp"],
      "env": {
        "SNYK_TOKEN": "${env:SNYK_TOKEN}"
      }
    }
  }
}
```

> **Note:** `${env:VAR_NAME}` tells VS Code to read the value from your shell environment at runtime. The token never appears in the settings file.

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
- Snyk account with an API token

---

## Attribution

API security skills in `skills/api-security/` are adapted from
[mukul975/Anthropic-Cybersecurity-Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills)
by **mahipal**, licensed under [Apache 2.0](https://www.apache.org/licenses/LICENSE-2.0).
Files are pinned locally to eliminate runtime supply-chain dependency on an external repository.
