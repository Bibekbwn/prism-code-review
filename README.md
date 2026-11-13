# PRISM — Pre-Commit Code Review System

Multi-agent code review pipeline that runs **before every commit**. 10 agents (4 deterministic regex + 6 AI-powered) scan your code for security flaws, quality issues, policy violations, test gaps, architecture problems, and performance bottlenecks. Each finding includes the **file**, **line number**, **problem description**, **suggestion text**, and **suggested code fix**.

**Your code never leaves your machine.** No server, no cloud, no database — just local JSON reports and a browser dashboard.

---

## Table of Contents

1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Command Reference](#command-reference)
6. [API Key Management](#api-key-management)
7. [Configuration](#configuration)
8. [Agents](#agents)
9. [Severity Levels & Blocking](#severity-levels--blocking)
10. [Effort Levels](#effort-levels)
11. [Report System & Dashboard](#report-system--dashboard)
12. [Codebase Cache](#codebase-cache)
13. [Pre-Commit Hook](#pre-commit-hook)
14. [CI/CD Integration](#cicd-integration)
15. [IDE Integration (LSP)](#ide-integration-lsp)
16. [Auto-Fix](#auto-fix)
17. [Deviation Management](#deviation-management)
18. [Project Structure](#project-structure)
19. [Running Tests](#running-tests)

---

## Features

| Feature | Description |
|---------|-------------|
| **10 agents** | 4 deterministic regex + 6 AI agents, each specialized for a concern |
| **Rich findings** | Every finding shows file, line, problem, suggestion text, and suggested code fix |
| **Visual dashboard** | Self-contained HTML with severity charts, agent charts, filters, and per-finding detail |
| **Multi-provider** | Switch between Gemini, Claude, and OpenAI with one command |
| **Command-only setup** | `prism key set` writes the `.env` for you — no file editing ever |
| **Pre-commit hook** | Blocks commits with critical/high findings automatically |
| **Auto-fix** | One-click fixes for secrets, `eval()`, `debugger`, banned patterns |
| **Codebase cache** | Only re-scans changed files on subsequent runs |
| **IDE integration** | LSP server shows findings inline in VS Code, Vim, Emacs, Zed, Helix |
| **CI/CD ready** | GitHub Actions workflows for tests and automated review |
| **Test execution** | `--test` flag runs pytest on changed files before review |
| **Finding verification** | Regex agents cross-check AI claims (halves confidence if unverified) |
| **Zero cost** | Self-hosted, free tier of any provider |

---

## How It Works

```
git commit
  ├─→ pre-commit-hook → prism check-staged [--test]
  │       ├─→ Run pytest on changed Python files (optional, --test)
  │       ├─→ Deterministic regex agents (no API calls, instant):
  │       │     ├─→ security   (SECU-XXX)  — secrets, injection, dangerous patterns
  │       │     ├─→ quality    (QUAL-XXX)  — complexity, naming, docstrings, type hints
  │       │     ├─→ policy     (POL-XXX)   — license headers, branch naming, banned patterns
  │       │     └─→ test       (TST-XXX)   — weak assertions, test naming
  │       └─→ AI agents (when API key is configured, --effort balanced/max):
  │             ├─→ ai_security      (SECU-AI-XXX)  — secrets, injection, auth flaws
  │             ├─→ ai_quality       (QUAL-AI-XXX)  — complexity, duplication, maintainability
  │             ├─→ ai_policy        (POL-AI-XXX)   — docs, compliance, standards
  │             ├─→ ai_test          (TST-AI-XXX)   — coverage, edge cases, test quality
  │             ├─→ ai_architecture  (ARC-AI-XXX)   — modularity, scalability, abstraction
  │             └─→ ai_performance   (PERF-AI-XXX)  — bottlenecks, memory, complexity
  │
  └─→ GitHub Actions (CI/CD) → runs tests + automated review on every push
```

---

## Installation

### Requirements
- Python 3.9+
- An API key for Gemini (default), Claude, or OpenAI

### Install

```bash
# Clone the repo
git clone <repo-url>
cd hackathon

# Install PRISM (Gemini only — default)
pip install -e .

# For Claude support:
pip install -e .[claude]

# For OpenAI support:
pip install -e .[openai]

# For all providers:
pip install -e .[all]
```

---

## Quick Start

### 1. Set your API key (command only — no file editing)

```bash
# Gemini (default provider)
prism key set --provider gemini --key YOUR_GEMINI_API_KEY

# Or switch to Claude
prism key set --provider claude --key YOUR_ANTHROPIC_API_KEY

# Or switch to OpenAI
prism key set --provider openai --key YOUR_OPENAI_API_KEY
```

The `prism key set` command writes `.env` for you and sets `MODEL_PROVIDER`.
Switching provider removes the previous provider's key automatically, so
exactly one key is active at a time. You never need to open `.env` or any file.

### 2. Review a file

```bash
prism check path/to/file.py
```

### 3. Review staged changes (before commit)

```bash
git add .
prism check-staged --effort balanced
```

### 4. Install the pre-commit hook (blocks commits with critical/high findings)

```bash
prism install-hook
```

### 5. View the visual dashboard

```bash
prism dashboard
```

The dashboard opens in your browser automatically after every
`prism check-staged` / `prism check-diff` review. It is a single self-contained
HTML file (`.prism-reports/dashboard.html`) with all report data embedded, so it
works offline and can be shared as-is.

Suppress the automatic open with `--no-dashboard`, the `PRISM_NO_DASHBOARD`
environment variable, or by running in CI (auto-detected via `CI` /
`GITHUB_ACTIONS`).

---

## Command Reference

Every command available in PRISM, with all flags and options.

### Review Commands

#### `prism check <file>` — Review a single file

```bash
prism check path/to/file.py              # Review with all configured agents
prism check path/to/file.py --json       # Output results as JSON
prism check path/to/file.py --fix        # Apply auto-fixable changes
prism check path/to/file.py --prompt     # Interactively ask about medium/low findings
prism check path/to/file.py --effort lite    # Only regex agents (fast, no API)
prism check path/to/file.py --effort balanced  # Regex + AI agents (default)
prism check path/to/file.py --effort max     # All agents, maximum thoroughness
prism check path/to/file.py --fast       # Two-pass summarization for large files
```

| Flag | Description |
|------|-------------|
| `--json` | Output results as machine-readable JSON |
| `--fix` | Apply auto-fixable changes to the file |
| `--prompt` | Ask developer: apply / skip / cancel for medium/low findings |
| `--effort {lite,balanced,max}` | AI review effort level (default: `balanced`) |
| `--fast` | Use two-pass summarization for large files (10K+ lines) |

**Output:** Every finding shows the file, line number, problem, suggestion, and suggested code fix. A report is saved automatically to `.prism-reports/`.

**Exit code:** `0` if commit allowed, `1` if blocking findings or failed quality gates exist, `2` if the file does not exist.

#### `prism check-diff` — Review a PR diff against a base branch

```bash
prism check-diff                                  # Diff against origin/main
prism check-diff --base origin/develop            # Diff against another branch
prism check-diff --base origin/main --effort lite # Regex agents only (no API)
prism check-diff --base origin/main --json        # Machine-readable JSON
```

Use this in CI: a fresh checkout has an empty git index, so `check-staged` would
review nothing. `check-diff` reviews the files changed between the base branch
and `HEAD`, which is what a pull-request review needs.

#### `prism check-staged` — Review staged git changes

```bash
git add .
prism check-staged                       # Review all staged files
prism check-staged --effort lite         # Only regex agents (fast)
prism check-staged --effort balanced     # Regex + AI agents (default)
prism check-staged --json                # Output as JSON (used by pre-commit hook)
prism check-staged --prompt              # Interactive prompts for medium/low findings
prism check-staged --test                # Run pytest on changed Python files first
prism check-staged --dashboard           # Open dashboard after review
prism check-staged --fast                # Two-pass summarization for large files
```

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON (stdout is pure JSON; status lines go to stderr) |
| `--prompt` | Interactive prompts for medium/low findings |
| `--effort {lite,balanced,max}` | AI review effort level |
| `--test` | Run pytest on changed Python files before review |
| `--dashboard` | Open visual dashboard after review |
| `--fast` | Two-pass summarization for large files |

**Exit code:** `0` if commit allowed, `1` if blocking findings or failed quality gates exist (the pre-commit hook uses this).

---

### API Key Commands

#### `prism key set` — Set a provider API key

```bash
prism key set --provider gemini --key YOUR_KEY
prism key set --provider openai --key YOUR_KEY
prism key set --provider claude --key YOUR_KEY
```

| Flag | Description |
|------|-------------|
| `--provider {gemini,openai,claude}` | Which provider's key to set (default: `gemini`) |
| `--key KEY` | The API key value (required) |

**Behavior:** Writes the key to `.env`, sets `MODEL_PROVIDER` to the chosen provider, and **removes other providers' keys** (only one key is active at a time).

#### `prism key status` — Show current key status

```bash
prism key status
```

Shows the masked key (e.g. `AQ.A...lOXg`), the active provider, and prompts to run `prism key set` if no key is configured.

#### `prism key delete` — Delete all API keys

```bash
prism key delete
```

Removes all `*_API_KEY` entries from `.env`. AI agents will be disabled until a new key is set.

---

### Report Commands

#### `prism reports` — Show review history summary

```bash
prism reports
```

Displays: total reviews, total findings, commits blocked, findings by severity, findings by agent, top rules.

#### `prism report <id>` — Show a specific report

```bash
prism report 20240101T120000Z
```

Shows the full JSON report including all findings (file, line, problem, suggestion, suggested_code, confidence, rule_id).

#### `prism delete-report <id>` — Delete a specific report

```bash
prism delete-report 20240101T120000Z
```

#### `prism clear-reports` — Delete all reports

```bash
prism clear-reports            # Asks for confirmation
prism clear-reports --force    # Skips confirmation
```

| Flag | Description |
|------|-------------|
| `--force` | Skip the confirmation prompt |

#### `prism dashboard` — Open visual dashboard

```bash
prism dashboard
```

Generates a self-contained HTML dashboard at `.prism-reports/dashboard.html` with all report data embedded inline. Open the printed `file:///` URL in a browser. Features:
- **Stat cards**: Total reviews, blocked, passed, total findings, blocking
- **Charts**: Findings by severity (bar chart), findings by agent (bar chart)
- **Filters**: All / Blocked / Passed chips to filter the timeline
- **Per-finding detail**: Click any report to expand and see every finding with file:line, problem, suggestion text, and suggested code fix (green code block)

---

### Agent Commands

#### `prism agents` — List all available agents

```bash
prism agents                        # List all 10 agents with descriptions
prism agents --enable <name>        # Enable a specific agent in prism.json
prism agents --disable <name>       # Disable a specific agent
```

| Flag | Description |
|------|-------------|
| `--enable <name>` | Add an agent to the `agents` list in `prism.json` |
| `--disable <name>` | Remove an agent from the `agents` list |

---

### Configuration Commands

#### `prism config` — View or manage configuration

```bash
prism config                        # Show full prism.json
prism config --get block_on         # Get a specific config value
prism config --set max_complexity 8 # Set a config value
```

| Flag | Description |
|------|-------------|
| `--get <key>` | Print the value of a config key |
| `--set <key> <value>` | Set a config value (JSON-parsed if valid JSON) |

#### `prism init` — Initialize configuration

```bash
prism init
```

Creates `prism.json` if it doesn't exist (never overwrites an existing config), and scaffolds `.env` from `.env.example` if missing. Then run `prism key set` to add your key.

---

### Cache Commands

#### `prism cache` — Manage the codebase cache

```bash
prism cache stats       # Show cache statistics (files cached, cache file path)
prism cache status      # Show changed vs cached files
prism cache clear       # Delete the entire cache
```

PRISM caches file hashes and findings in `.prism-cache.json`. On subsequent runs, only changed files are re-scanned. Unchanged files reuse cached findings.

---

### Setup & Hook Commands

#### `prism install-hook` — Install pre-commit hook

```bash
prism install-hook
```

Writes `.git/hooks/pre-commit` that runs `python -m prism.cli check-staged --prompt --json` on every `git commit`. Blocks the commit if any critical/high findings exist.

#### `prism uninstall-hook` — Remove pre-commit hook

```bash
prism uninstall-hook
```

#### `prism init` — Create prism.json config

See [Configuration Commands](#configuration-commands).

---

### Other Commands

#### `prism ignore` — Control what pre-commit review skips

```bash
prism ignore                          # Show the list + what each staged file resolves to
prism ignore add docs/                # Skip a folder
prism ignore add "*.png" "assets/"    # Skip several patterns at once
prism ignore remove docs/             # Stop skipping a pattern
prism ignore reset                    # Restore the built-in default list
```

| Action | Description |
|--------|-------------|
| `list` (default) | Show `.prismignore` entries, built-in defaults, and every staged file marked `review`/`SKIP` |
| `add <pattern>...` | Append patterns to `.prismignore` (ignored if already present) |
| `remove <pattern>...` | Remove patterns from `.prismignore` |
| `reset` | Restore the default ignore list (clears custom entries) |

Patterns use `.gitignore` syntax: `*.md`, `docs/`, `/rooted/path.py`, and
`!keep.md` to re-include a file that a broader pattern excluded. Matching is
case-insensitive on every platform.

**Skipped by default** (no configuration needed): docs (`*.md`, `*.rst`,
`*.txt`, `LICENSE*`, `CHANGELOG*`, `CONTRIBUTING*`), images/media/fonts,
certificates and keys (`*.pem`, `*.p12`), data (`*.csv`, `*.sql`, `*.db`),
build output (`build/`, `dist/`, `target/`, `out/`, `bin/`, `obj/`,
`coverage/`), dependency and cache folders (`node_modules/`, `vendor/`,
`.venv/`, `__pycache__/`, `.pytest_cache/`), lock files (`package-lock.json`,
`poetry.lock`, `uv.lock`, `Cargo.lock`, …), generated/minified sources
(`*.min.js`, `*_pb2.py`, `*.designer.cs`), and editor noise (`.vscode/`,
`.idea/`, `.DS_Store`, `Thumbs.db`).

`prism ignore reset` restores a short, readable starter list (`.prismignore`),
not the full default set — the broad rules above always apply underneath.

To keep the list next to the rest of the PRISM config, add an `ignore` array to
`prism.json` instead — both sources are applied, `.prismignore` first:

```json
{
  "ignore": ["vendor/", "generated/"]
}
```

#### `prism mode` — Turn regex and AI agents on or off

```bash
prism mode                 # Show the current mode
prism mode regex           # Regex agents only — no API calls
prism mode none            # No agents at all — reports only
prism mode all             # Regex + AI agents (default)
```

| Mode | Regex agents | AI agents | Use for |
|------|--------------|-----------|---------|
| `all` | yes | yes | Default. Needs an API key. |
| `regex` | yes | no | Offline runs, no key, fast pre-commit |
| `none` | no | no | Skip review entirely, keep reports/dashboard working |

The mode is stored in `prism.json` (`"mode": "regex"`) so it applies to every
developer and to CI without extra flags.

`--effort lite` still works as a per-invocation override and forces regex-only
for that run, but it cannot widen `none` — a stored `none` always means nothing
runs:

```bash
prism check app.py --effort lite    # regex only for this run
prism check app.py                  # honours the stored mode
```

In `none` mode the command still writes an empty report (0 findings, risk 0.0)
so `prism reports`, `prism dashboard` and `--json` consumers see a valid,
successful run instead of an error.

#### `prism agents --disable` — Stop one specific regex or AI agent

`prism mode` picks a whole family; `prism agents --disable` switches off a
single agent and leaves everything else running.

```bash
prism agents                         # Show every agent and its state
prism agents --disable ai_quality    # Stop the AI quality agent only
prism agents --disable quality policy  # Stop two regex agents
prism agents --enable ai_quality     # Re-enable it
```

The state is stored in `prism.json` under `"agents"`, either as a list of
enabled names or as a `{name: bool}` map:

```json
{
  "agents": {
    "ai_quality": false,
    "quality": false
  }
}
```

Disabling composes with the mode: `mode=regex` plus a disabled `quality`
runs only the deterministic agents except `quality`.

```bash
prism agents --disable ai_quality    # Silence a noisy agent
prism check app.py                   # Everything else still runs
```

#### `prism version` — Show version

```bash
prism version
```

#### `prism help` — Show all commands

```bash
prism help
```

#### `prism test` — Run self-tests

```bash
prism test              # Run all self-tests (includes API calls)
prism test --quick      # Run only quick tests (skips API calls)
```

| Flag | Description |
|------|-------------|
| `--quick` | Skip tests that require API calls |

#### `prism benchmark` — Benchmark agent performance

```bash
prism benchmark --file src/app.py              # Benchmark with default 3 iterations
prism benchmark --file src/app.py --iterations 5  # Benchmark with 5 iterations
```

| Flag | Description |
|------|-------------|
| `--file <path>` | File to benchmark against (required) |
| `--iterations <n>` | Number of iterations per agent (default: 3) |

#### `prism stats` — Show review statistics

```bash
prism stats
```

#### `prism policy` — Show deviation policy

```bash
prism policy
```

#### `prism feedback` — Show feedback loop stats

```bash
prism feedback
```

#### `prism suppressed` — Show historically suppressed rules

```bash
prism suppressed
```

---

## API Key Management

PRISM supports three AI providers. You switch between them with one command:

| Provider | Env Var | Install Command | Model |
|----------|---------|-----------------|-------|
| **Gemini** (default) | `GEMINI_API_KEY` | `pip install -e .` | `gemini-3.5-flash-lite` |
| **Claude** | `ANTHROPIC_API_KEY` | `pip install -e .[claude]` | `claude-3-5-sonnet-20241022` |
| **OpenAI** | `OPENAI_API_KEY` | `pip install -e .[openai]` | `gpt-4o` |

### Set a key

```bash
prism key set --provider gemini --key YOUR_KEY
```

This writes `.env`, sets `MODEL_PROVIDER`, and removes other providers' keys (only one active at a time).

### Check current key

```bash
prism key status
```

Output:
```
gemini: AQ.A...lOXg

Active provider: gemini
```

### Delete all keys

```bash
prism key delete
```

### No key configured?

If no key is set, AI agents are disabled and PRISM logs a warning. The deterministic regex agents still run with `--effort lite`. Run `prism key set` to enable AI agents.

---

## Configuration

### `prism.json`

The main configuration file. Ships with the repo — never overwritten by `prism init`.

```json
{
  "agents": [
    "security", "quality", "policy", "test",
    "ai_security", "ai_quality", "ai_policy", "ai_test",
    "ai_architecture", "ai_performance"
  ],
  "block_on": ["critical", "high"],
  "quality_gates": {
    "max_complexity": 15,
    "max_file_length": 800,
    "min_coverage": 0
  },
  "confidence_threshold": 0.7,
  "policy": {
    "headers": false
  },
  "quality": {
    "docstrings": false
  }
}
```

| Key | Description |
|-----|-------------|
| `agents` | List of enabled agent names (or a `{name: bool}` map). `prism agents --disable <name>` toggles one off |
| `block_on` | Severity levels that block a commit (default: critical and high) |
| `quality_gates.max_complexity` | Max cyclomatic complexity before blocking (high/critical only) |
| `quality_gates.max_file_length` | Max lines per file before blocking (high/critical only) |
| `quality_gates.min_coverage` | Minimum test coverage percentage (`0` disables the gate) |
| `confidence_threshold` | Minimum confidence (0.0–1.0) for a finding to be reported |
| `policy.headers` | Require copyright/SPDX headers (`POL-101`, `POL-206`). Off by default |
| `policy.banned_console` | Flag `console.log` in JS/TS. Off by default |
| `policy.check_print` | Flag `print()` outside CLI entry points. Off by default |
| `policy.check_todo_refs` | Enforce `TODO(PROJECT-123)` issue references. Off by default |
| `quality.docstrings` | Flag missing docstrings (`QUAL-110`). Off by default |
| `quality.type_hints` | Flag missing return type hints (`QUAL-111`). Off by default |
| `quality.magic_numbers` | Flag hardcoded numbers (`QUAL-109`). Off by default |
| `quality.line_length` | Flag lines over 120 chars (`QUAL-105`). Off by default |
| `quality.todo_markers` | Flag TODO/FIXME/HACK markers (`QUAL-104`). Off by default |
| `quality.duplication` | Flag repeated 4-line blocks (`QUAL-106`). Off by default |

### `.prism-policy.json` (Deviation Management)

Suppress specific findings for specific files (e.g. intentional security exceptions):

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

---

## Agents

PRISM runs two layers of review. The **deterministic** regex agents run unconditionally and are fast (no API calls). The **AI** agents run only when an API key is configured and `--effort` is `balanced` or `max`.

| Agent | Rule IDs | What It Checks | Blocks? |
|-------|----------|---------------|---------|
| `security` | `SECU-XXX` | Secrets (22 patterns), eval(), exec(), os.system(), SQL injection, XSS, CVEs | Yes (critical/high) |
| `quality` | `QUAL-XXX` | File/function length, complexity, naming, imports (docstrings, type hints, magic numbers, TODO markers, duplication are opt-in) | Warns (advisory) |
| `policy` | `POL-XXX` | SPDX license headers, branch naming, banned patterns, copyright | Warns |
| `test` | `TST-XXX` | Weak assertions, test naming, coverage measurement | Yes (no tests) |
| `ai_security` | `SECU-AI-XXX` | AI semantic review of secrets, injection, auth flaws | Depends on severity |
| `ai_quality` | `QUAL-AI-XXX` | AI semantic review of complexity, duplication, maintainability | Depends on severity |
| `ai_policy` | `POL-AI-XXX` | AI semantic review of documentation, compliance, standards | Depends on severity |
| `ai_test` | `TST-AI-XXX` | AI semantic review of test coverage, edge cases | Depends on severity |
| `ai_architecture` | `ARC-AI-XXX` | AI semantic review of modularity, scalability, abstraction | Depends on severity |
| `ai_performance` | `PERF-AI-XXX` | AI semantic review of bottlenecks, memory, complexity | Depends on severity |

### Finding Verification

AI findings in deterministic categories (secrets, dangerous patterns, duplication, file length, todos, naming) are cross-checked against the regex agents. If the regex agrees, the finding is confirmed; if not, confidence is halved (the CodeRabbit "verification agent" pattern).

### Each finding includes

| Field | Description |
|-------|-------------|
| **File** | The file path where the issue was found |
| **Line** | The line number of the issue |
| **Problem** | What the issue is |
| **Suggestion** | Text explanation of how to fix it |
| **Suggested code** | Actual code to fix the issue (AI agents only) |
| **Severity** | Critical / High / Medium / Low |
| **Confidence** | 0.0–1.0 (how sure the agent is) |
| **Rule ID** | e.g. `SECU-105`, `QUAL-AI-1126` |
| **Blocking** | Whether this finding blocks the commit |

---

## Severity Levels & Blocking

| Severity | Behavior |
|----------|----------|
| **Critical** | Blocks commit immediately |
| **High** | Blocks commit immediately |
| **Medium** | Prompts developer: apply fix, skip, or cancel |
| **Low** | Prompts developer: apply fix, skip, or cancel |

Use the `--prompt` flag to enable interactive prompts for medium/low findings. Without `--prompt`, medium/low findings are reported but don't block the commit.

---

## Effort Levels

| Level | Agents | Speed | API Calls |
|-------|--------|-------|-----------|
| `lite` | 4 regex agents only | Fast (~20ms/file) | None |
| `balanced` (default) | 4 regex + 6 AI agents | Medium (~30–60s/file) | Yes |
| `max` | All agents, maximum thoroughness | Slow | Yes |

Use `--effort lite` for quick checks during development. Use `--effort balanced` (default) or `--effort max` for pre-commit and CI.

---

## Report System & Dashboard

Every `prism check` and `prism check-staged` automatically saves a report to `.prism-reports/`. No server, no cloud, no database — just local JSON files.

### View reports

```bash
# Summary of all past reviews
prism reports

# Full report for a specific ID
prism report 20240101T120000Z

# Delete a specific report
prism delete-report 20240101T120000Z

# Delete all reports
prism clear-reports --force
```

### Visual dashboard

```bash
prism dashboard
```

Generates a self-contained HTML file at `.prism-reports/dashboard.html` with all report data embedded. Open the printed `file:///` URL in any browser. The dashboard includes:

- **Stat cards**: Total reviews, blocked, passed, total findings, blocking count
- **Findings by Severity** bar chart (critical / high / medium / low)
- **Findings by Agent** bar chart (security / quality / policy / test / ai_*)
- **Filter chips**: All / Blocked / Passed — click to filter the timeline
- **Per-report severity bar**: Visual mix of severities for each review
- **Per-finding detail** (click any report to expand):
  - Severity badge (color-coded)
  - Rule ID (e.g. `SECU-105`)
  - Confidence percentage
  - File name and line number (e.g. `_field_test.py:3`)
  - Problem description
  - Suggestion text
  - Suggested code fix (green code block, AI agents only)

### Report data structure

Each report JSON contains:
- `id` — timestamp-based ID (e.g. `20240101T120000Z`)
- `timestamp` — ISO timestamp
- `commit_hash` — git commit hash (if available)
- `branch` — git branch name
- `files_reviewed` — list of files
- `total_findings` — count
- `blocking` — count of blocking findings
- `risk_score` — 0.0 to 1.0
- `commit_allowed` — boolean
- `findings` — array of finding objects (agent, severity, category, problem, file, line, suggestion, suggested_code, confidence, rule_id)

---

## Codebase Cache

PRISM caches file hashes and findings in `.prism-cache.json`. On subsequent runs, only changed files are re-scanned. Unchanged files reuse cached findings.

```bash
prism cache stats       # Show cache statistics
prism cache status      # Show changed vs cached files
prism cache clear       # Delete the entire cache
```

---

## Pre-Commit Hook

Install the hook so PRISM runs automatically on every `git commit`:

```bash
prism install-hook
```

The hook runs `python -m prism.cli check-staged --prompt --json`. If any critical/high findings exist, the commit is blocked with exit code 1. To remove it:

```bash
prism uninstall-hook
```

---

## CI/CD Integration

PRISM includes GitHub Actions workflows:

### `.github/workflows/ci-cd.yml` — Test CI
Runs on every push and PR to `main`. Tests on **Ubuntu and Windows** with **Python 3.11, 3.12, 3.13**. Runs `pytest`, self-tests, and CLI smoke commands. Includes a lint job.

### `.github/workflows/prism-review.yml` — Automated Review
Runs on every PR. Installs PRISM and runs `prism check-diff --base origin/<base> --effort lite --json` on the PR diff. Lite mode requires no API key. For full AI review, set `GEMINI_API_KEY` in repo secrets and change `--effort lite` to `--effort balanced` in the workflow. (`check-staged` would see an empty index in a CI checkout, so it is not used here.)

---

## IDE Integration (LSP)

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

---

## Auto-Fix

PRISM can automatically fix certain findings:

```bash
prism check path/to/file.py --fix
```

Auto-fixable findings include:
- Hardcoded secrets (replaced with `os.environ.get(...)`)
- `eval()` / `exec()` (removed)
- `debugger` statements (removed)
- `print()` (replaced with `logging`)

During `--prompt` mode, you can choose to apply all auto-fixable changes interactively.

---

## Deviation Management

Suppress specific findings for specific files when they're intentional:

Create `.prism-policy.json`:
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

Findings matching a deviation are skipped. View the current policy with:
```bash
prism policy
```

---

## Project Structure

```
hackathon/
├── prism/                          # Main package
│   ├── __init__.py
│   ├── cli.py                      # CLI entry point (argparse + dispatch)
│   ├── cli_commands.py             # check / check-staged / check-diff + self-tests
│   ├── cli_config.py               # Config loading, git helpers, deviation policy
│   ├── cli_review.py               # Review orchestration, report formatting
│   ├── commands_common.py          # Shared helpers for the command handlers
│   ├── commands_reports.py         # reports, cache, config, stats, dashboard
│   ├── commands_setup.py           # key, init, hook, version, help, agents, ignore, mode
│   ├── ignore.py                   # .prismignore parsing + path matching
│   ├── modes.py                    # all/regex/none mode selection
│   ├── agents.py                   # BaseAgent, Finding, Severity, Blocker, pipeline
│   ├── agents_security.py          # Regex: secrets, dangerous patterns (SECU-XXX)
│   ├── agents_quality.py           # Regex: complexity, naming, imports (QUAL-XXX)
│   ├── agents_policy.py            # Regex: license, branch naming (POL-XXX)
│   ├── agents_test.py              # Regex: weak assertions, test naming (TST-XXX)
│   ├── ai_providers.py             # Gemini/Claude/OpenAI init + retry + call dispatch
│   ├── ai_findings.py              # JSON parse, verify, cross-check
│   ├── ai_graph.py                 # Import graph + cross-file context
│   ├── ai_pipeline.py              # Chunking, tiers, two-pass summarization
│   ├── ai_common.py                # Public API facade (re-exports modules above)
│   ├── ai_security.py              # AI security agent (SECU-AI-XXX)
│   ├── ai_quality.py               # AI quality agent (QUAL-AI-XXX)
│   ├── ai_policy.py                # AI policy agent (POL-AI-XXX)
│   ├── ai_test.py                  # AI test agent (TST-AI-XXX)
│   ├── ai_architecture.py          # AI architecture agent (ARC-AI-XXX)
│   ├── ai_performance.py           # AI performance agent (PERF-AI-XXX)
│   ├── autofix.py                  # Auto-fix engine (secrets, eval, debugger, print)
│   ├── feedback.py                 # SCA CVE scanning + coverage + feedback loop
│   ├── logging_config.py           # Structured JSON logging
│   ├── lsp.py                      # LSP server (IDE integration, stdlib only)
│   ├── codebase_cache.py           # Per-commit cache of file hashes + findings
│   ├── reports.py                  # Local JSON report persistence
│   ├── dashboard.html              # Dashboard HTML template
│   ├── setup.py                    # Installable package definition
│   └── pre-commit-hook.sh          # Git hook script template
├── tests/                          # 158 unit + integration tests
│   ├── conftest.py
│   ├── test_call_graph.py
│   ├── test_cli_handlers.py
│   ├── test_coverage_paths.py
│   ├── test_golden_corpus.py
│   ├── test_integration.py
│   ├── test_lsp.py
│   ├── test_providers.py
│   ├── test_security.py
│   └── test_regressions.py
├── .github/
│   └── workflows/
│       ├── ci-cd.yml               # Test CI (Ubuntu + Windows, Python 3.11–3.13)
│       └── prism-review.yml        # Automated PR review
├── .env.example                    # Environment variable template
├── .gitignore
├── .prismignore                    # Files pre-commit review skips (see `prism ignore`)
├── prism.json                      # PRISM configuration
└── README.md
```

---

## Running Tests

```bash
# Install test dependencies
pip install pytest

# Run all tests
pytest tests/ -v

# Run PRISM self-tests (includes API calls)
prism test

# Run only quick self-tests (no API calls)
prism test --quick
```

The test suite covers:
- Security scanning (secrets, dangerous patterns)
- Call graph and cross-file context
- LSP server protocol
- Integration (full pipeline)
- Regression tests for cache blocking, JSON purity, auto-fix imports,
  dotenv secrets, AI dedup, binary skipping, quality gates, and `--fast`
- 13 built-in self-tests (skeleton, chunking, tiers, verification, import graph, agent registration)