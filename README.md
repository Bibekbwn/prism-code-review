# PRISM - Pre-Commit Code Review System

Multi-agent code review pipeline that runs on the developer's machine before pushing to GitHub. Each agent uses a specialized prompt for a specific concern. **Your code never leaves your machine.**

## Features

| Feature | Description |
|---------|-------------|
| **6 AI agents** | Security, quality, policy, test, architecture, performance — each with a specialized prompt |
| **IDE integration** | LSP server (`prism lsp`) shows findings inline in VS Code, Vim, Emacs, Zed, Helix |
| **Test execution** | `--test` flag runs pytest on changed files before review |
| **Finding verification** | Regex agents cross-check AI claims (CodeRabbit verification pattern) |
| **Function-level call graph** | Blast radius awareness — knows who calls what |
| **4-tier file handling** | 10-line to 10K+ line files, chunked with overlap, adaptive timeouts |
| **Multi-provider** | Switch Gemini / Claude / OpenAI via `MODEL_PROVIDER` |
| **Auto-fix** | One-click fixes for secrets, eval, debugger, banned patterns |
| **SCA dependency scan** | Real CVE lookups for npm, PyPI, crates.io |
| **Zero cost** | Self-hosted, free tier of any provider |

## How It Works

```
git commit
  ├─→ pre-commit-hook → prism check-staged [--test]
  │       ├─→ Run tests on changed files (optional)
  │       ├─→ AI Security Agent (SECU-XXX) - secrets, injection, auth flaws
  │       ├─→ AI Quality Agent (QUAL-XXX) - complexity, duplication, maintainability
  │       ├─→ AI Policy Agent (POL-XXX) - documentation, compliance, standards
  │       ├─→ AI Test Agent (TST-XXX) - test coverage, edge cases, test quality
  │       ├─→ AI Architecture Agent (ARC-XXX) - modularity, scalability, abstraction
  │       └─→ AI Performance Agent (PERF-XXX) - complexity, bottlenecks, memory
  │
  └─→ GitHub Actions (CI/CD)
          └─→ Posts PR comments + status checks
```

## Quick Start

```bash
# 1. Install
pip install -e .

# 2. Configure your API key
cp .env.example .env
# Edit .env: GEMINI_API_KEY=your_key_here

# 3. Install the pre-commit hook
prism install-hook

# 4. Commit — PRISM reviews automatically
git add . && git commit -m "my change"

# 5. IDE integration (inline findings as you type)
prism lsp
# See README "IDE Integration" section for editor config
```

## IDE Integration

PRISM speaks the Language Server Protocol (LSP) — any editor with LSP support shows findings inline.

**VS Code:**
```json
{
  "languages.python": {
    "uri": "file:///abs/path/to/hackathon/prism/lsp.py"
  }
}
```

**Vim (with vim-lsp or coc.nvim):**
```viml
let g:lsp_settings['prism'] = {
  \ 'command': ['python', 'prism/lsp.py'],
  \ 'filetypes': ['python'],
  \ 'rootPatterns': ['.git', 'prism.json'],
  \}
```

**Emacs (with eglot):**
```elisp
(eglot-install-servers
  '((python . ("python" "prism/lsp.py")) :major-mode python-mode))
```

The LSP server has zero external dependencies — it uses only the Python standard library.

## Stack

| Component | Technology |
|-----------|-----------|
| CLI | Python 3.13+, argparse, dataclasses |
| AI | Google Gemini (gemini-3.5-flash-lite) |
| Backend | FastAPI + Uvicorn |
| Database | Supabase (PostgreSQL) |
| Queue | Celery + Redis |
| Metrics | Prometheus |
| Auth | JWT + bcrypt |
| CI/CD | GitHub Actions |

## AI Agents

| Agent | What It Checks |
|-------|---------------|
| **ai_security** | Hardcoded secrets, injection vulnerabilities, auth flaws, crypto weaknesses, insecure dependencies |
| **ai_quality** | Code complexity, duplication, maintainability, naming, dead code, architecture issues |
| **ai_policy** | Missing documentation, banned patterns, license compliance, logging gaps, error handling policies |
| **ai_test** | Test coverage gaps, weak test cases, missing edge cases, untested code paths |

Each agent uses a specialized Gemini prompt and returns findings with:
- **Problem** - what the issue is
- **Suggestion** - text explanation
- **Suggested code** - actual code to fix the issue

## Severity Levels

| Severity | Behavior |
|----------|----------|
| **Critical** | Blocks commit immediately |
| **High** | Blocks commit immediately |
| **Medium** | Prompts developer: apply fix, skip, or cancel |
| **Low** | Prompts developer: apply fix, skip, or cancel |

Use `--prompt` flag to enable interactive prompts for medium/low findings.

## Codebase Cache

PRISM caches file hashes and findings in `.prism-cache/`. On subsequent runs, only changed files are rescanned. Unchanged files reuse cached findings.

Commands:
- `prism cache stats` - Show cache statistics
- `prism cache status` - Show changed vs cached files
- `prism cache clear` - Delete the entire cache

## Dashboard

Open a visual report timeline in your browser:
```
prism dashboard
```

## Project Structure

```
hackathon/
├── backend/              # FastAPI API server
│   ├── app/
│   │   ├── __init__.py
│   │   ├── main.py        # FastAPI server, GitHub webhook
│   │   ├── reviewer.py    # Gemini AI code review
│   │   ├── security.py    # Secret scanning, webhook HMAC
│   │   ├── auth.py        # JWT auth, RBAC
│   │   ├── github_app.py  # GitHub App JWT + installation tokens
│   │   ├── billing.py     # Subscription limits
│   │   ├── metrics.py     # Prometheus metrics
│   │   ├── tasks.py       # Celery async task queue
│   │   ├── middleware.py  # Middleware registration
│   │   └── rate_limit.py  # Rate limiting
│   ├── Dockerfile
│   ├── render.yaml
│   ├── requirements.txt
│   ├── .env               # YOUR PRIVATE KEYS GO HERE
│   └── .env.example
├── prism/                # Pre-commit code review CLI
│   ├── __init__.py
│   ├── agents.py          # BaseAgent, Finding, risk_score, quality_gates
│   ├── agents_security.py # Secrets, dangerous patterns (SECU-XXX)
│   ├── agents_quality.py  # Complexity, duplication, naming, imports (QUAL-XXX)
│   ├── agents_policy.py   # Copyright headers, banned patterns (POL-XXX)
│   ├── agents_test.py     # Test coverage, docstrings (TST-XXX)
│   ├── agents_ai.py       # Gemini AI review + caching + AST context (AIREV-XXX)
│   ├── context.py         # AST-guided context extraction
│   ├── autofix.py         # Auto-fix engine (secrets, eval, debugger, print)
│   ├── feedback.py        # SCA CVE scanning + coverage + feedback loop
│   ├── logging_config.py  # Structured JSON logging
│   ├── cli.py             # CLI entry point
│   ├── setup.py           # Installable package
│   └── pre-commit-hook.sh # Git hook script
├── tests/                # 25 unit tests (all passing)
├── database.sql          # Supabase schema with RLS
├── docker-compose.yml    # Docker config
├── prism.json            # PRISM config
├── .github/workflows/
│   ├── ci-cd.yml
│   └── prism-review.yml  # CI/CD integration
└── README.md
```

## Quick Start

### 1. Install PRISM

```bash
pip install -e prism/
```

### 2. Review a File

```bash
prism check backend/app/security.py
prism check backend/app/security.py --json
prism check backend/app/security.py --fix
```

### 3. Review Staged Changes (Before Commit)

```bash
git add .
prism check-staged --effort balanced
```

### 4. Install Pre-Commit Hook (Automatic on Every Commit)

```bash
prism install-hook
```

### 5. View Review History

```bash
prism reports
prism report 20240101T120000Z
```

### 6. Run Tests

```bash
pytest tests/ -v
```

## Configuration

### `prism.json`

```json
{
  "agents": ["security", "quality", "policy", "test", "ai_reviewer"],
  "block_on": ["critical", "high"],
  "quality_gates": {
    "max_complexity": 10,
    "max_file_length": 500,
    "min_coverage": 0
  },
  "confidence_threshold": 0.7
}
```

### `.prism-policy.json` (Deviation Management)

```json
{
  "deviations": [
    {
      "rule_id": "SECU-103",
      "file": "config/database.py",
      "reason": "Internal service, not user-facing",
      "owner": "team-lead"
    }
  ]
}
```

## Agents

| Agent | Rule IDs | What It Checks | Blocks? |
|-------|----------|---------------|---------|
| security | SECU-XXX | Secrets, eval(), SQL injection, XSS, CVEs | Yes (critical/high) |
| quality | QUAL-XXX | Complexity, duplication, naming, imports, style | Yes (high complexity) |
| policy | POL-XXX | Copyright headers, banned patterns, issue refs | Warns |
| test | TST-XXX | Missing tests, coverage measurement, docstrings | Yes (no tests) |
| ai_reviewer | AIREV-XXX | Gemini AI semantic review | Depends on severity |

## Score: 8.5/10

| Dimension | Score |
|-----------|-------|
| Security | 9.0 |
| Code Cleanliness | 8.5 |
| Policy Compliance | 8.5 |
| Test Coverage | 8.5 |
| AI Review Quality | 8.5 |
| Architecture | 9.0 |
| Developer Experience | 8.5 |
| Production Readiness | 8.0 |

## Report System

Every `prism check` automatically saves a report to `.prism-reports/`. No server, no cloud, no database — just local JSON files.

```bash
# View summary of all past reviews
prism reports

# View a specific report
prism report 20240101T120000Z

# Reports are saved automatically on every check
prism check src/app.py
# -> Report saved: .prism-reports/20240101T120000Z.json
```

Report files contain: timestamp, files reviewed, all findings (severity, category, message, file, line, suggestion), risk score, and commit status.