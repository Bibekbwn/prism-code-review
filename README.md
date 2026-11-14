# PRISM — Pre-Commit Code Review System

Multi-agent code review pipeline that runs **before every commit**. 10 agents (4 deterministic regex + 6 AI-powered) scan your code for security flaws, quality issues, policy violations, test gaps, architecture problems, and performance bottlenecks. It reviews **12 languages** — Python, JavaScript/TypeScript, Go, Rust, Java, C#, C, C++, Ruby, PHP, Kotlin and Swift. Each finding includes the **file**, **line number**, **problem description**, **suggestion text**, and **suggested code fix**.

**Your code never leaves your machine.** No server, no cloud, no database — just local JSON reports and a browser dashboard.

---

## Table of Contents

1. [Features](#features)
2. [How It Works](#how-it-works)
3. [Languages](#languages)
4. [Installation](#installation)
5. [Quick Start](#quick-start)
6. [Command Reference](#command-reference)
7. [API Key Management](#api-key-management)
8. [Configuration](#configuration)
9. [Agents](#agents)
10. [Severity Levels & Blocking](#severity-levels--blocking)
11. [Effort Levels](#effort-levels)
12. [Report System & Dashboard](#report-system--dashboard)
13. [Codebase Cache](#codebase-cache)
14. [Pre-Commit Hook](#pre-commit-hook)
15. [CI/CD Integration](#cicd-integration)
16. [IDE Integration (LSP)](#ide-integration-lsp)
17. [Auto-Fix](#auto-fix)
18. [Deviation Management](#deviation-management)
19. [Project Structure](#project-structure)
20. [Running Tests](#running-tests)

---

## Features

| Feature | Description |
|---------|-------------|
| **10 agents** | 4 deterministic regex + 6 AI agents, each specialized for a concern |
| **12 languages** | Python, JS/TS, Go, Rust, Java, C#, C, C++, Ruby, PHP, Kotlin, Swift — not Python with the rest ignored |
| **Rich findings** | Every finding shows file, line, problem, suggestion text, and suggested code fix |
| **Visual dashboard** | Self-contained HTML with severity charts, agent charts, filters, and per-finding detail |
| **Multi-provider** | 8 providers: Gemini, Claude, OpenAI, OpenRouter, Groq, Together, DeepSeek, Mistral |
| **Command-only setup** | `prism key set` writes the `.env` for you — no file editing ever |
| **Install once, run anywhere** | Ship one wheel; `prism key set --global` configures every project on the machine |
| **Self-explaining failures** | A missing SDK says `pip install 'prism-review[gemini]'`, not "no API key" |
| **Whole-project audit** | `prism scan <path>` reviews every file, not just the diff |
| **Environment diagnostics** | `prism doctor` checks keys, SDKs and config before you wonder why AI is silent |
| **Pre-commit hook** | Blocks commits with critical/high findings automatically |
| **Auto-fix** | Language-aware fixes for secrets, `eval()`, `debugger`, banned patterns |
| **One finding per issue** | The same problem reported by several agents is collapsed, with the other agents listed as corroboration |
| **Codebase cache** | Only re-scans changed files on subsequent runs |
| **IDE integration** | LSP server shows findings inline in VS Code, Vim, Emacs, Zed, Helix |
| **CI/CD ready** | GitHub Actions tests the full suite on Ubuntu **and** Windows, Python 3.11–3.13 |
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
  │       │     ├─→ quality    (QUAL-XXX)  — complexity, length, naming, TODOs, imports
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

## Languages

Every review path reads the file's language first (`prism/langs.py`), so the agents
measure structure and generate fixes in the language of the file instead of assuming
Python.

| Language | Extensions |
|----------|------------|
| Python | `.py`, `.pyi` |
| JavaScript / TypeScript | `.js`, `.jsx`, `.mjs`, `.cjs`, `.ts`, `.tsx` |
| Go | `.go` |
| Rust | `.rs` |
| Java | `.java` |
| C# | `.cs` |
| C | `.c`, `.h` |
| C++ | `.cpp`, `.cc`, `.cxx`, `.hpp`, `.hh`, `.hxx` |
| Ruby | `.rb`, `.rake` |
| PHP | `.php` |
| Kotlin | `.kt`, `.kts` |
| Swift | `.swift` |

A file with no declared language (Markdown, YAML, JSON, images) has no language-specific
structure rules — the generic checks still run, and those files score lower on risk.
Binary files are skipped outright rather than scanned as text.

**What this changes in practice:**

- **Function length and complexity are measured as structure.** Comments and string
  literals are blanked across the whole file first, so a `{` inside a block comment,
  or an `if` quoted in a docstring, is not counted as a branch. In the brace
  languages that is the only way to get the count right.
- **Auto-fixes stay in the file's language.** A hardcoded secret becomes
  `os.getenv("NAME")` in Python, `process.env.NAME` in JavaScript,
  `System.getenv("NAME")` in Java, `os.Getenv("NAME")` in Go, and so on — the
  declaration is kept and only the literal is swapped. See [Auto-Fix](#auto-fix).

---

## Installation

### Requirements
- Python 3.9+
- An API key for any one of the [8 supported providers](#api-key-management). The regex agents need no key at all.

### Install

```bash
# Clone the repo
git clone <repo-url>

# Install PRISM (no AI SDK — regex agents still work)
pip install -e .

# Gemini (default provider):
pip install -e .[gemini]

# Claude:
pip install -e .[claude]

# OpenAI — this one extra also covers OpenRouter, Groq, Together,
# DeepSeek and Mistral, which are OpenAI-compatible endpoints:
pip install -e .[openai]

# All SDKs at once:
pip install -e .[all]

# Test and lint dependencies:
pip install -e ".[dev]"
```

There are only three SDKs to install. The five OpenAI-compatible providers
(`openai`, `openrouter`, `groq`, `together`, `deepseek`, `mistral`) reuse the
`openai` client against a different `base_url`, so no extra package is needed for them.

### Hand the tool to a teammate (no `cd`, no venv on their side)

Build the wheel once, attach it to a GitHub Release, and the teammate runs
**one** command from any folder — no virtualenv, no source checkout, no build
tools:

```bash
# On the machine that has the repo (you):
py -m build          # -> dist/prism_review-2.0.0-py3-none-any.whl
# then: GitHub -> Releases -> Draft a new release -> tag v2.0.0
#       -> attach the .whl -> Publish

# On the teammate's machine, once. The [all] extra installs every provider SDK
# plus python-dotenv; without an extra the regex agents run but AI agents skip:
pip install "https://github.com/<owner>/<repo>/releases/download/v2.0.0/prism_review-2.0.0-py3-none-any.whl[all]"

# Set the API key once for every project (tool-wide):
prism key set --global --provider gemini --key YOUR_GEMINI_API_KEY

# Then in any project folder: git init, prism init, prism check ...
```

Use `[all]` when you do not control which provider each developer will use. For
a team standardised on one provider, install only that extra — `[gemini]`,
`[claude]`, or `[openai]` (the last also covers openrouter, groq, together,
deepseek and mistral).

When the SDK for the active provider is missing, PRISM names it and prints the
fix instead of claiming the key is wrong:

```
gemini SDK not installed. Install it with: pip install 'prism-review[gemini]'
```

`prism key set --global` writes the key to the install folder's `.env` (next to
site-packages), which `load_env` reads as a fallback after the project-local
`.env` — so a project-level `prism key set` still overrides it. Without
`--global` the key goes to the current project's `.env` as before.

Three entry points, one dispatcher: the `prism` console script after a pip
install, `py -m prism` from anywhere, and `py -m prism.cli` from a source
checkout with nothing installed.

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

# Any of the other five also work: openrouter, groq, together, deepseek, mistral
prism key set --provider groq --key YOUR_GROQ_API_KEY
```

The `prism key set` command writes `.env` for you and sets `MODEL_PROVIDER`.
Switching provider removes the previous provider's key automatically, so
exactly one key is active at a time. You never need to open `.env` or any file.
Add `--global` to write the key to the install folder instead of the current
project (set once, use from every project). See [API Key Management](#api-key-management)
for the full provider table.

### 2. Check the setup

```bash
prism doctor        # key present? SDK installed? config valid?
```

`doctor` explains why AI agents are silent when something is misconfigured, and it
never fails the run.

### 3. Review a file

```bash
prism check path/to/file.py
```

### 4. Review staged changes (before commit)

```bash
git add .
prism check-staged --effort balanced
```

### 5. Install the pre-commit hook (blocks commits with critical/high findings)

```bash
prism install-hook
```

### 6. View the visual dashboard

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

All commands work three ways — `prism <cmd>`, `py -m prism <cmd>`, and
`py -m prism.cli <cmd>` from a source checkout. The examples below use `prism`.

### Review Commands

#### `prism check <file>` — Review a single file

```bash
prism check path/to/file.py              # Review with all configured agents
prism check path/to/file.py --json       # Output results as JSON
prism check path/to/file.py --fix        # Apply auto-fixable changes
prism check path/to/file.py --fix --yes  # Apply without the confirmation prompt
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
| `--yes` | Apply `--fix` changes without the confirmation prompt |
| `--prompt` | Ask developer: apply / skip / cancel for medium/low findings |
| `--effort {lite,balanced,max}` | AI review effort level (default: `balanced`) |
| `--fast` | Use two-pass summarization for large files (10K+ lines) |

**Output:** Every finding shows the file, line number, problem, suggestion, and suggested code fix. A report is saved automatically to `.prism-reports/`.

**Exit code:** `0` if commit allowed, `1` if blocking findings or failed quality gates exist, `2` if the file does not exist.

#### `prism check-diff` — Review a PR diff against a base branch

`prism diff` is an alias for the same command.

```bash
prism check-diff                                  # Diff against origin/main
prism check-diff --base origin/develop            # Diff against another branch
prism check-diff --base origin/main --effort lite # Regex agents only (no API)
prism check-diff --base origin/main --json        # Machine-readable JSON
prism check-diff --base origin/main --fast        # Two-pass summarization
prism check-diff --no-dashboard                   # Do not open the dashboard
prism diff --base origin/main                     # Alias for check-diff
```

| Flag | Description |
|------|-------------|
| `--base <ref>` | Base ref to diff against (default: `origin/main`) |
| `--json` | Output results as JSON |
| `--effort {lite,balanced,max}` | AI review effort level |
| `--fast` | Use two-pass summarization for large files |
| `--no-dashboard` | Do not open the HTML dashboard after review |

**Exit code:** `0` if commit allowed, `1` if blocking findings or failed quality gates exist.

Use this in CI: a fresh checkout has an empty git index, so `check-staged` would
review nothing. `check-diff` reviews the files changed between the base branch
and `HEAD`, which is what a pull-request review needs.

#### `prism check-staged` — Review staged git changes

```bash
git add .
prism check-staged                       # Review all staged files
prism check-staged --effort lite         # Only regex agents (fast)
prism check-staged --effort balanced     # Regex + AI agents (default)
prism check-staged --json                # Machine-readable JSON
prism check-staged --prompt              # Offer to auto-fix medium/low findings
prism check-staged --test                # Run pytest on changed Python files first
prism check-staged --dashboard           # Force-open the dashboard after review
prism check-staged --fast                # Two-pass summarization for large files
```

| Flag | Description |
|------|-------------|
| `--json` | Output results as JSON (stdout is pure JSON; status lines go to stderr) |
| `--effort {lite,balanced,max}` | AI review effort level |
| `--test` | Run pytest on changed Python files before review |
| `--prompt` | Offer to apply auto-fixes for medium/low findings (only when nothing is blocking; skipped when stdin is not a terminal) |
| `--dashboard` | Force-open the visual dashboard after review (overrides auto-open detection) |
| `--no-dashboard` | Do not open the HTML dashboard after review |
| `--fast` | Two-pass summarization for large files |

**Exit code:** `0` if commit allowed, `1` if blocking findings or failed quality gates exist (the pre-commit hook uses this).

---

#### `prism scan <path>` — Review every file in a directory (whole-project audit)

`check` / `check-staged` / `check-diff` review one file or a diff. `scan` reviews the
**full content of every file** under a path, which is what you want when onboarding a
project, running a nightly audit, or establishing a baseline.

```bash
prism scan                         # Audit the current directory
prism scan src/                    # Audit one directory
prism scan . --effort lite         # Regex agents only (free, fast)
prism scan src/ --effort max       # Deeper AI pass over every file
prism scan src/ --json             # Machine-readable JSON
```

| Flag | Description |
|------|-------------|
| `path` | Root directory to scan (default: `.`) |
| `--json` | Output results as JSON (status lines go to stderr) |
| `--effort {lite,balanced,max}` | AI review effort level |
| `--fast` | Two-pass summarization for large files |
| `--no-dashboard` | Do not open the HTML dashboard after review |

**Behavior:** Directories such as `.git`, `node_modules`, `.venv`, `__pycache__`,
`dist` and `build` are skipped, and `.prismignore` still applies. Files whose content
hash is unchanged since the last review are served from the codebase cache, so repeat
runs are cheap. The verdict is **advisory** — it prints `AUDIT: N issue(s) found -
review-only, no commit gate.` and always exits `0`, so a scan never breaks a pipeline.

---

### API Key Commands

#### `prism key set` — Set a provider API key

```bash
prism key set --provider gemini --key YOUR_KEY
prism key set --provider openai --key YOUR_KEY
prism key set --provider claude --key YOUR_KEY
prism key set --provider groq --key YOUR_KEY

# Tool-wide: write the key once, use it from every project on the machine
prism key set --global --provider gemini --key YOUR_KEY
```

| Flag | Description |
|------|-------------|
| `--provider {gemini,claude,openai,openrouter,groq,together,deepseek,mistral}` | Which provider's key to set (default: `gemini`) |
| `--key KEY` | The API key value (required) |
| `--global` | Write to the install folder's `.env` instead of the current project |

**Behavior:** Writes the key to `.env`, sets `MODEL_PROVIDER` to the chosen
provider, and **removes other providers' keys** (only one key is active at a
time). With `--global` the target is the `.env` beside site-packages, which
`load_env` reads after the project-local `.env` — so a project-level
`prism key set` still wins.

#### `prism key status` — Show current key status

```bash
prism key status
```

Shows the masked key (e.g. `AQ.A...lOXg`), which store it came from
(`[project]` or `[global]`), the active provider, and prompts to run
`prism key set` if no key is configured.

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

Displays: total reviews, total findings, commits blocked, total tokens (with input/output split and how many were AI reviews), findings by severity, findings by agent, top rules.

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
prism config                                        # Show full prism.json
prism config --get block_on                         # Get a top-level value
prism config --get quality_gates.max_complexity     # Get a nested value
prism config --set confidence_threshold 0.8         # Set a top-level value
prism config --set quality_gates.max_complexity 15  # Set a nested value
```

| Flag | Description |
|------|-------------|
| `--get <key>` | Print the value of a config key (supports dotted paths like `quality_gates.max_complexity`) |
| `--set <key> <value>` | Set a config value (JSON-parsed if valid JSON; supports dotted paths) |

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

Writes `.git/hooks/pre-commit` that runs `python -m prism.cli check-staged --prompt` on every `git commit`. Blocks the commit if any critical/high findings exist.

#### `prism uninstall-hook` — Remove pre-commit hook

```bash
prism uninstall-hook
```

#### `prism init` — Create prism.json config

See [Configuration Commands](#configuration-commands).

#### `prism doctor` — Check that the environment is ready

```bash
prism doctor
```

Reports the Python/platform versions, whether `.env` and `prism.json` exist, git
availability, the active effort level and agent count, and then a per-provider table:
key present, SDK installed, and default model. Missing optional keys are **warnings** —
the regex agents work with no API key at all — so the command is a diagnostic, not a
gate, and always exits `0`. It flags real problems such as an invalid `effort` value,
an enabled provider whose SDK is missing, or an invalid `MODEL_PROVIDER`.

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

PRISM supports **8 AI providers**. You switch between them with one command, and only
one key is active at a time.

| Provider | Env var | Default model | Model override | Install |
|----------|---------|---------------|----------------|---------|
| **Gemini** (default) | `GEMINI_API_KEY` | `gemini-3.5-flash-lite` | `GEMINI_MODEL` | `pip install -e .[gemini]` |
| **Claude** | `ANTHROPIC_API_KEY` | `claude-3-5-sonnet-20241022` | `CLAUDE_MODEL` | `pip install -e .[claude]` |
| **OpenAI** | `OPENAI_API_KEY` | `gpt-4o` | `OPENAI_MODEL` | `pip install -e .[openai]` |
| **OpenRouter** | `OPENROUTER_API_KEY` | `openai/gpt-4o-mini` | `OPENROUTER_MODEL` | `pip install -e .[openai]` |
| **Groq** | `GROQ_API_KEY` | `llama-3.3-70b-versatile` | `GROQ_MODEL` | `pip install -e .[openai]` |
| **Together** | `TOGETHER_API_KEY` | `meta-llama/Llama-3.3-70B-Instruct-Turbo` | `TOGETHER_MODEL` | `pip install -e .[openai]` |
| **DeepSeek** | `DEEPSEEK_API_KEY` | `deepseek-chat` | `DEEPSEEK_MODEL` | `pip install -e .[openai]` |
| **Mistral** | `MISTRAL_API_KEY` | `mistral-large-latest` | `MISTRAL_MODEL` | `pip install -e .[openai]` |

The last five are OpenAI-compatible endpoints, so they reuse the `openai` client and
need no extra package — that is why the install column repeats `.[openai]`.

Each provider also accepts a base-URL override (`OPENAI_BASE_URL`, `OPENROUTER_BASE_URL`,
`GROQ_BASE_URL`, `TOGETHER_BASE_URL`, `DEEPSEEK_BASE_URL`, `MISTRAL_BASE_URL`) for a proxy
or a self-hosted gateway. The defaults are `https://openrouter.ai/api/v1`,
`https://api.groq.com/openai/v1`, `https://api.together.xyz/v1`,
`https://api.deepseek.com` and `https://api.mistral.ai/v1`.

### Aliases

These names are accepted wherever a provider is named, and resolve to the canonical one:

| Alias | Resolves to |
|-------|-------------|
| `anthropic` | `claude` |
| `google` | `gemini` |
| `gpt`, `open-ai` | `openai` |

### Set a key

```bash
prism key set --provider gemini --key YOUR_KEY
```

This writes `.env`, sets `MODEL_PROVIDER`, and removes other providers' keys (only one active at a time).

Add `--global` to write the key to the install folder's `.env` instead of the
current project's:

```bash
prism key set --global --provider gemini --key YOUR_KEY
```

The global key is read as a fallback after the project-local `.env` (see
[Hand the tool to a teammate](#hand-the-tool-to-a-teammate-no-cd-no-venv-on-their-side)),
so a project-level `prism key set` still overrides it.

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

### Diagnose the setup

```bash
prism doctor
```

`doctor` lists every provider with three checks — key present, SDK installed, and whether
`MODEL_PROVIDER` names a provider that exists — so a missing key or an uninstalled SDK is
visible before you wonder why the AI agents are silent.

### Tuning the provider calls

Optional environment variables, all with safe defaults:

| Variable | Default | Effect |
|----------|---------|--------|
| `PRISM_TIMEOUT` | tier-based (30s / 45s / 60s / 90s, capped at 120s) | Overrides the per-call timeout, in seconds |
| `PRISM_API_TIMEOUT` | `30` | Base timeout in seconds, multiplied by the file-size tier (see `PRISM_TIMEOUT`); also the per-attempt wall-clock cap, so a provider that accepts the socket but never answers cannot stall the CLI |
| `PRISM_MAX_RETRIES` | `2` | Retries per call after the first attempt |
| `PRISM_RETRY_BASE_DELAY` | `0.2` | Initial backoff between retries, in seconds |
| `PRISM_RETRY_MAX_DELAY` | `1.0` | Cap on a single backoff sleep |
| `PRISM_RETRY_BUDGET` | `5` | Total seconds a call may spend sleeping, so a bad provider cannot stall the CLI |
| `PRISM_CIRCUIT_THRESHOLD` | `5` | Consecutive failures before the circuit opens and calls fail fast |
| `PRISM_CIRCUIT_COOLDOWN` | `60` | Seconds the circuit stays open before retrying |
| `PRISM_REPO_PATH` | current directory | Root used to build the import graph for cross-file context |
| `PRISM_BASE` | `origin/main` | Default base ref for `check-diff` when `--base` is not given |
| `PRISM_MAX_CONTENT_CHARS` | `16000` | Max characters of file content sent in one call. A cost control — the skeleton and import graph still describe the whole file |

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
  "mode": "all",
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
| `mode` | `all` / `regex` / `none` — which agent families run (`prism mode <mode>` writes it) |
| `quality_gates.max_complexity` | Max cyclomatic complexity before blocking (high/critical only) |
| `quality_gates.max_file_length` | Max lines per file before blocking (high/critical only) |
| `quality_gates.min_coverage` | Minimum test coverage percentage (`0` disables the gate) |
| `confidence_threshold` | Minimum confidence (0.0–1.0) for a finding to be reported |
| `ignore` | Extra paths and globs to skip, in addition to `.prismignore` |
| `policy.headers` | Require copyright/SPDX headers (`POL-101`, `POL-206`). Off by default |
| `policy.banned_console` | Flag `console.log` in JS/TS. Off by default |
| `policy.check_print` | Flag `print()` outside CLI entry points. Off by default |
| `policy.check_todo_refs` | Enforce `TODO(PROJECT-123)` issue references. Off by default |
| `quality.docstrings` | Flag missing docstrings (`QUAL-110`). Off by default |
| `quality.type_hints` | Flag missing return type hints (`QUAL-111`). Off by default |
| `quality.magic_numbers` | Flag hardcoded numbers (`QUAL-109`). Off by default |
| `quality.line_length` | Flag lines over 120 chars (`QUAL-105`). **On** by default |
| `quality.todo_markers` | Flag TODO/FIXME/HACK markers (`QUAL-104`). **On** by default |
| `quality.duplication` | Flag repeated 4-line blocks (`QUAL-106`). Off by default |

Every quality rule is capped at 3 findings per file, so one rule cannot fill a report
with 200 copies of the same warning. The subjective checks (docstrings, type hints,
magic numbers, duplication) stay off because they produce a wall of warnings
developers learn to ignore — turn them on per project when you want them.

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
| `quality` | `QUAL-XXX` | File/function length, complexity, naming, TODO markers, line length, imports (docstrings, type hints, magic numbers, duplication are opt-in) | Warns (advisory) |
| `policy` | `POL-XXX` | SPDX license headers, branch naming, banned patterns, copyright | Warns |
| `test` | `TST-XXX` | Weak assertions, test naming, coverage measurement | Warns (advisory) |
| `ai_security` | `SECU-AI-XXX` | AI semantic review of secrets, injection, auth flaws | Depends on severity |
| `ai_quality` | `QUAL-AI-XXX` | AI semantic review of complexity, duplication, maintainability | Depends on severity |
| `ai_policy` | `POL-AI-XXX` | AI semantic review of documentation, compliance, standards | Depends on severity |
| `ai_test` | `TST-AI-XXX` | AI semantic review of test coverage, edge cases | Depends on severity |
| `ai_architecture` | `ARC-AI-XXX` | AI semantic review of modularity, scalability, abstraction | Depends on severity |
| `ai_performance` | `PERF-AI-XXX` | AI semantic review of bottlenecks, memory, complexity | Depends on severity |

### Finding Verification

AI findings in deterministic categories (secrets, dangerous patterns, duplication, file length, todos, naming) are cross-checked against the regex agents. If the regex agrees, the finding is confirmed; if not, confidence is halved (the CodeRabbit "verification agent" pattern).

### One finding per issue

Every agent answers the same question, so the same problem arrives several times: two
regex agents both flag the same hardcoded key, and an AI agent then describes it again
in its own words. The pipeline collapses those copies per `(file, line)` before the
report is written, so a secret appears once and the blocking count is real.

- Findings on **different lines** are kept. A secret *and* an O(n²) loop on the same
  line are both kept too — the "kind" of finding decides whether two reports are the
  same issue.
- The surviving copy lists the other agents in `corroborated_by`, which the dashboard
  renders as `also: ai_security, policy`.

Note that this is per report. The dashboard's `Total Findings` card sums every stored
report, so re-running `prism check` on the same file counts the finding once per run —
that is the review timeline, not duplication within a review.

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

- **Stat cards**: Total reviews, blocked, passed, total findings, blocking, tokens
- **Findings by Severity** bar chart (critical / high / medium / low)
- **Findings by Agent** bar chart (security / quality / policy / test / ai_*)
- **Tokens by Review** chart, with per-report token detail
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
- `id` — timestamp-based ID (e.g. `20240101T120000Z`), with a numeric suffix when two reviews land in the same clock tick (`...000Z-1`) so one report never overwrites another
- `timestamp` — ISO timestamp
- `commit_hash` — git commit hash (if available)
- `branch` — git branch name
- `files_reviewed` — list of files
- `total_findings` — count
- `blocking` — count of blocking findings
- `risk_score` — 0.0 to 1.0
- `commit_allowed` — boolean
- `token_usage` — per-review token snapshot (`total_tokens`, `input_tokens`, `output_tokens`, `calls`, `estimated_calls`, `by_provider`); absent on reports written before token tracking, which read as "unknown" rather than as zero
- `findings` — array of finding objects (agent, severity, category, problem, file, line, suggestion, suggested_code, confidence, rule_id, corroborated_by)

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

The hook runs `python -m prism.cli check-staged --prompt`. If any critical/high findings exist, the commit is blocked with exit code 1. To remove it:

```bash
prism uninstall-hook
```

---

## CI/CD Integration

PRISM includes GitHub Actions workflows:

### `.github/workflows/ci-cd.yml` — Test CI
Runs on every push and PR to `main`. A 2×3 matrix — **Ubuntu and Windows** × **Python 3.11, 3.12, 3.13** — so every job runs the full suite on both platforms:

- `pytest tests/ -q --cov=prism --cov-report=term-missing --cov-fail-under=60` (coverage gate at 60%)
- `prism test --quick` (built-in self-tests)
- CLI smoke: `version`, `agents`, `help`, `key status`
- `prism check` on a clean file with `--effort lite --no-dashboard --json`, so the
  review path is exercised on Windows too, not just the import

A separate `lint` job runs `pyflakes prism/ tests/` and is **blocking** — it is the same
linter as the declared dev dependency, so CI and a local run agree.

### `.github/workflows/prism-review.yml` — Automated Review
Runs on every PR. Installs PRISM and runs `prism check-diff --base origin/<base> --effort lite --json` on the PR diff. Lite mode requires no API key. For full AI review, set `GEMINI_API_KEY` in repo secrets and change `--effort lite` to `--effort balanced` in the workflow. (`check-staged` would see an empty index in a CI checkout, so it is not used here.)

This job is **advisory** (`continue-on-error: true`): PRISM reviews whole changed files,
so a self-scan would otherwise fail every PR on pre-existing debt rather than on the
change under review.

---

## IDE Integration (LSP)

PRISM speaks the Language Server Protocol (LSP) — any editor with LSP support shows findings inline. Diagnostics come from the same review path as the CLI, so all **12 languages** are covered; point your editor's filetype association at the server for each one you use.

**VS Code:**
```json
{
  "languages.python": {
    "uri": "file:///abs/path/to/hackathon/prism/lsp.py"
  },
  "languages.go": {
    "uri": "file:///abs/path/to/hackathon/prism/lsp.py"
  }
}
```

The LSP server has zero external dependencies — it uses only the Python standard library.

**Emacs (with eglot):**
```elisp
(eglot-install-servers
  '((python . ("python" "prism/lsp.py"))
    (go . ("python" "prism/lsp.py"))) :major-mode prog-mode)
```

**Vim (with vim-lsp or coc.nvim):**
```viml
let g:lsp_settings['prism'] = {
  \ 'command': ['python', 'prism/lsp.py'],
  \ 'filetypes': ['python', 'go', 'javascript', 'rust'],
  \ 'rootPatterns': ['.git', 'prism.json'],
  \}
```

---

## Auto-Fix

PRISM can automatically fix certain findings:

```bash
prism check path/to/file.py --fix
```

Auto-fixable findings include:
- Hardcoded secrets (replaced with an environment lookup, in the file's own language)
- `eval()` / `exec()` (replaced with an inert statement, or the line disabled with the language's comment marker)
- `debugger` statements (commented out — they cannot be simply deleted without changing the block)
- `print()` (replaced with `logging` in Python; commented out elsewhere with a note to use a logging framework)

Fixes are generated in the language of the file, not in Python. A secret keeps its
declaration and only the literal changes:

| Language | Before | After |
|----------|--------|-------|
| Python | `password = "hunter2"` | `password = os.getenv("PASSWORD")` |
| JavaScript | `const token = "abc";` | `const token = process.env.TOKEN;` |
| Go | `apiKey := "abc"` | `apiKey := os.Getenv("APIKEY")` |
| Java | `String apiKey = "abc";` | `String apiKey = System.getenv("APIKEY");` |
| PHP | `$key = "abc";` | `$key = getenv("KEY");` |

`import os` is added for Python when the generated fix needs it, and `import "os"`
for Go when it is missing. Rust uses the fully-qualified `std::env::var(...)`, so no
import is needed. A fix that would not compile is rejected rather than applied: the
file is left untouched and the developer fixes it by hand.

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
│   ├── __init__.py                   # .env loading (project, then install-folder fallback)
│   ├── __main__.py                   # `py -m prism` entry point
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
│   ├── langs.py                      # Per-language descriptors: comments, strings, lookup syntax
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
│   ├── autofix.py                  # Language-aware auto-fix (secrets, eval, debugger, print)
│   ├── feedback.py                 # SCA CVE scanning + coverage + feedback loop
│   ├── logging_config.py           # Structured JSON logging
│   ├── lsp.py                      # LSP server (IDE integration, stdlib only)
│   ├── codebase_cache.py           # Per-commit cache of file hashes + findings
│   ├── reports.py                  # Local JSON report persistence
│   ├── token_usage.py              # Per-review token ledger
│   ├── dashboard.html              # Dashboard HTML template
│   └── pre-commit-hook.sh          # Git hook script template
├── tests/                          # 404 unit + integration tests
│   ├── conftest.py
│   ├── test_autofix_languages.py   # Per-language fixes and structure measurement
│   ├── test_call_graph.py
│   ├── test_cli_handlers.py
│   ├── test_coverage_paths.py
│   ├── test_global_key.py          # `key set --global` write target + precedence
│   ├── test_golden_corpus.py
│   ├── test_integration.py
│   ├── test_languages.py           # Every declared language is reviewed
│   ├── test_lsp.py
│   ├── test_product.py
│   ├── test_product_e2e.py
│   ├── test_providers.py
│   ├── test_regressions.py
│   ├── test_security.py
│   └── test_token_reporting.py
├── .github/
│   └── workflows/
│       ├── ci-cd.yml               # Test CI (Ubuntu + Windows, Python 3.11–3.13)
│       └── prism-review.yml        # Automated PR review (advisory)
├── .env.example                    # Environment variable template
├── .gitignore                      # .env, build/, dist/, caches, reports
├── .prismignore                    # Files pre-commit review skips (see `prism ignore`)
├── prism.json                      # PRISM configuration
├── pyproject.toml                  # Package definition, deps, extras, scripts, pytest config
└── README.md
```

`dist/` and `build/` are git-ignored: a release is a wheel attached to a GitHub
Release, not a file committed to the repo.

---

## Running Tests

```bash
# Install test dependencies
pip install -e ".[dev]"        # pytest, pytest-cov, pyflakes

# Run all tests
pytest tests/ -v

# Same command CI runs, with the coverage gate
pytest tests/ -q --cov=prism --cov-report=term-missing --cov-fail-under=60

# Lint (CI runs this too, and it blocks)
pyflakes prism/ tests/

# Run PRISM self-tests (includes API calls)
prism test

# Run only quick self-tests (no API calls)
prism test --quick
```

The suite covers:
- Security scanning (secrets, dangerous patterns)
- Per-language behaviour: structure measurement and generated fixes for all 12 languages
- Call graph and cross-file context
- LSP server protocol
- Integration (full pipeline) and product end-to-end
- Token accounting in reports and the dashboard
- Regression tests for cache blocking, JSON purity, auto-fix imports,
  dotenv secrets, AI dedup, binary skipping, quality gates, `--fast`, and
  Windows report-ID collisions
- Provider failure attribution: a missing key and a missing SDK are reported
  differently, and every provider maps to the right pip extra
- Tool-wide key storage: `key set --global` writes to the install folder and a
  project-level key still overrides it
- 13 built-in self-tests (skeleton, chunking, tiers, verification, import graph, agent registration)

---

## Releasing

```bash
py -m build        # -> dist/prism_review-<version>-py3-none-any.whl
```

Then attach the wheel to a GitHub Release (Releases → Draft a new release → tag
`v<version>` → attach the `.whl` → Publish). `dist/` is git-ignored, so the
wheel is never committed; the Release asset URL is what developers install from.

The wheel declares no hard dependencies — providers are opt-in extras
(`[gemini]`, `[claude]`, `[openai]`, `[all]`, `[dev]`), so a base install stays
small and the regex agents work with no SDK and no key at all.