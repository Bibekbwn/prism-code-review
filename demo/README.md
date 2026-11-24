# Demo files

Every file in this folder is **intentionally vulnerable**. They exist so you can
see what the review tool reports without pointing it at real code.

Nothing here is real: the keys, passwords and tokens are all fake, and no file is
imported by the project.

## Run it yourself

```bash
pip install "prism-code-review[all]"

prism check demo/vulnerable.py
prism check demo/app.js
prism check demo/service.go
prism check demo/config.env

prism dashboard
```

Each command prints the findings for that file and exits non-zero, because every
one of these files should block a commit.

## What each file demonstrates

Counts are from a full run with AI agents enabled (the default):

| File | Findings | Shows |
|---|---|---|
| `vulnerable.py` | 24 | Hardcoded API key and password, SQL injection, `shell=True`, `eval()`, `os.system()`, missing tests |
| `app.js` | 19 | Hardcoded token, XSS via `innerHTML`, `eval()`, plain-HTTP transport, naming |
| `service.go` | 14 | SQL injection, shell execution, ignored errors, missing docs |
| `config.env` | 6 | Database URL, Stripe key, unquoted dotenv secrets |

## AI agents

All six AI agents run by default. The regex agents alone work with no key, which
is what makes the offline path possible:

```bash
prism check demo/vulnerable.py --effort lite   # regex only, no API calls
prism check demo/vulnerable.py                 # regex + 6 AI agents
```

The AI agents and the regex agents review the same file independently, then the
findings are cross-checked and merged — a finding both agree on is reported once,
with the other agents listed under "Also reported by".

In the published dashboard each report shows the token cost of its AI calls
(roughly 3.6k–9.1k tokens per file in the demo run).

## A live version of the output

The dashboard generated from these four files is published at
<https://bibekbwn.github.io/prism-code-review/> — see `docs/index.html`.