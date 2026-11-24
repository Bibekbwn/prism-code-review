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

| File | Findings | Shows |
|---|---|---|
| `vulnerable.py` | 6 | Hardcoded API key, SQL injection, `shell=True`, `eval()`, `os.system()`, missing tests |
| `app.js` | 4 | Hardcoded token, XSS via `innerHTML`, `eval()`, naming convention |
| `service.go` | 2 | SQL injection, shell command execution |
| `config.env` | 5 | Database URL, Stripe key, unquoted dotenv secrets |

## A live version of the output

The dashboard generated from these four files is published at
<https://bibekbwn.github.io/prism-code-review/> — see `docs/index.html`.