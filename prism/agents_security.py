"""
Security Agent - Scans for hardcoded secrets, dangerous patterns,
insecure dependencies, and common vulnerability signatures.

Rule IDs follow SonarQube convention: SECU-XXX
"""

import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent


SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key", "SECU-101"),
    # Prefixed names are the norm in real config (DB_PASSWORD, STRIPE_SECRET,
    # SESSION_KEY); requiring the bare name at line start missed them all.
    (r'(?i)(secret[_-]?key|secretkey|session[_-]?key|sessionkey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key", "SECU-102"),
    (r'(?i)^\s*(?:[A-Za-z0-9]+[_-])?(?:password|passwd|pwd)\s*[:=]\s*["\']([^\s\'\"\n]{8,})["\']', "Password", "SECU-103"),
    (r'(?i)(token|access_token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Auth Token", "SECU-104"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "SECU-105"),
    (r'(?i)(github|gitlab)_token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Git Token", "SECU-106"),
    (r'(?i)(private_key|privatekey)\s*[:=]\s*["\']([^\s\'\"\n]{20,})["\']', "Private Key", "SECU-107"),
    (r'(?i)(mysql|postgres|mongodb)://[^\s\'\"<>]+', "Database Connection String", "SECU-108"),
    # --- Gitleaks-style provider-specific secrets (researched from gitleaks, trufflehog, detect-secrets) ---
    (r'(?i)slack[_-]?token\s*[:=]\s*["\']([xox[baprs]-[A-Za-z0-9\-]{10,})["\']', "Slack Token", "SECU-109"),
    (r'(?i)slack[_-]?webhook\s*[:=]\s*["\'](https://hooks\.slack\.com/services/[A-Za-z0-9/]+)["\']', "Slack Webhook URL", "SECU-110"),
    # Real Stripe test keys are ~16 chars after the prefix (sk_test_51H8...),
    # so a 24-char minimum let them through.
    (r'(?i)(sk|pk)_(live|test)_[A-Za-z0-9]{12,}', "Stripe Key", "SECU-111"),
    (r'(?i)twilio[_-]?(auth[_-]?token|sid)\s*[:=]\s*["\']([A-Za-z0-9]{20,})["\']', "Twilio Credential", "SECU-112"),
    (r'(?i)sendgrid[_-]?api[_-]?key\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "SendGrid API Key", "SECU-113"),
    (r'(?i)(google[_-]?api[_-]?key|gcp[_-]?key)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Google API Key", "SECU-114"),
    (r'AIza[0-9A-Za-z_\-]{35}', "Google API Key (literal)", "SECU-115"),
    (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', "PEM Private Key Block", "SECU-116"),
    (r'(?i)jwt[_-]?secret\s*[:=]\s*["\']([^\s\'\"\n]{8,})["\']', "JWT Secret", "SECU-117"),
    (r'(?i)(npm[_-]?token|npm[_-]?access[_-]?token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "npm Token", "SECU-118"),
    (r'(?i)(heroku|digitalocean)[_-]?(api[_-]?key|token)\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Cloud Provider Token", "SECU-119"),
    (r'(?i)(auth[_-]?token|authtoken)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{16,})["\']', "Auth Token (generic)", "SECU-120"),
    (r'(?i)(client[_-]?secret)\s*[:=]\s*["\']([^\s\'\"\n]{16,})["\']', "Client Secret", "SECU-121"),
    (r'(?i)(access[_-]?key[_-]?id)\s*[:=]\s*["\']([A-Za-z0-9]{16,})["\']', "Access Key ID", "SECU-122"),
    # Unquoted dotenv-style assignments (PASSWORD=hunter2). Quoted values are
    # covered by the provider-specific patterns above; this catches .env files,
    # which are the most common place for real secrets to leak.
    (r'(?i)^\s*(?:\w+[_-])?(?:api[_-]?key|apikey|secret[_-]?(?:access[_-]?)?key|secretkey|password|passwd|pwd|token|access[_-]?key[_-]?id|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[:=]\s*([^\s"\']{6,})\s*$', "Unquoted Dotenv Secret", "SECU-123"),
]

# Gitleaks-style false-positive filtering, split into two tiers:
#   SECRET_VALUE_ALLOWLIST  — obvious placeholders inside the secret itself
#                            (e.g. "xxx", "changeme", "your_key_here").
#                            Kept narrow on purpose so real-looking keys like
#                            AKIAIOSFODNN7EXAMPLE still get flagged.
#   SECRET_LINE_ALLOWLIST  — the surrounding line reads like a test fixture,
#                            env-var lookup, or config template.
SECRET_VALUE_ALLOWLIST = [
    r'(?i)xxx|yyy|zzz|changeme|placeholder|your[_-]?key|dummy[_-]?key|sample[_-]?key',
    r'(?i)<your[_-]?[^>]*>|<insert[^>]*>',
    r'\{\{[^}]*\}\}',
]

SECRET_LINE_ALLOWLIST = [
    r'(?i)test[_-]?key|mock[_-]?key|fake[_-]?key|dev[_-]?key',
    r'(?i)os\.getenv|os\.environ|process\.env|import\.env',
    r'\.env\b|\.env\.example|\.env\.template',
    r'(?i)redacted|sanitized|scrubbed',
]

DANGEROUS_PATTERNS = [
    (r"\beval\s*\(", "Use of eval() - code injection risk", "SECU-201"),
    (r"\bexec\s*\(", "Use of exec() - code injection risk", "SECU-202"),
    (r"subprocess\.(call|run|Popen)\s*\([^)]*shell\s*=\s*True", "Shell=True in subprocess - command injection risk", "SECU-203"),
    (r"os\.system\s*\(", "Use of os.system() - command injection risk", "SECU-204"),
    (r"pickle\.loads?\s*\(", "Use of pickle - deserialization risk", "SECU-205"),
    (r"yaml\.load\s*\(", "Use of yaml.load() without SafeLoader - deserialization risk", "SECU-206"),
    (r"yaml\.load\s*\([^)]*Loader\s*=\s*c\.SafeLoader", "yaml.load with SafeLoader (safe, no finding)", "SECU-206-SAFE"),
    (r"SELECT\s+.+\s+FROM\s+.+\s+WHERE\s+.+\s*=\s*['\"].*\+", "SQL injection - string concatenation in query", "SECU-207"),
    (r"document\.getElementById\([^)]*\)\.innerHTML\s*=", "XSS - innerHTML assignment", "SECU-208"),
    (r"\.\w+\s*\+\s*['\"]", "Potential XSS - string concatenation in HTML", "SECU-209"),
    (r"md5\s*\(", "Use of MD5 - weak hash", "SECU-210"),
    (r"\bsha1\s*\(", "Use of SHA1 - weak hash", "SECU-211"),
    (r"random\.random\(\)\s*\)?\s*==|random\.randint\(\s*0\s*,", "Insecure randomness (not crypto-safe)", "SECU-212"),
    (r"requests\.(get|post|put|delete)\s*\([^)]*verify\s*=\s*False", "TLS verification disabled", "SECU-213"),
    (r"chmod\s+777|os\.chmod\([^)]*0o?777", "Overly permissive file permissions (777)", "SECU-214"),
    (r"harvest|harvesting|harvested", "Possible data exfiltration keyword", "SECU-215"),
]

INSECURE_DEPENDENCIES = {
    "lodash": ("Use lodash-es or individual packages", "SECU-301"),
    "moment": ("Replace with date-fns or luxon", "SECU-302"),
    "axios": ("Use fetch or got", "SECU-303"),
    "request": ("Deprecated - use got or node-fetch", "SECU-304"),
    "node-uuid": ("Replace with crypto.randomUUID()", "SECU-305"),
    "uuid": ("Use crypto.randomUUID() instead", "SECU-306"),
    "request-promise": ("Use native fetch or got", "SECU-307"),
    "body-parser": ("Use express.json() directly", "SECU-308"),
    "helmet": ("Outdated - use express-helmet or helmet v5+", "SECU-309"),
}


@register_agent
class SecurityAgent(BaseAgent):
    name = "security"
    description = "Scans for secrets, dangerous patterns, and vulnerabilities"

    def _check(self, file_path: str, content: str, diff: str,
               skeleton: str = "", line_count: int = None,
               fast: bool = False) -> List[Finding]:
        findings: List[Finding] = []
        lines = content.split("\n")
        current_file = file_path

        for i, line in enumerate(lines, 1):
            for pattern, label, rule_id in SECRET_PATTERNS:
                match = re.search(pattern, line, re.IGNORECASE)
                if not match:
                    continue
                # Gitleaks-style two-tier false-positive filtering.
                # Tier 1 (value): obvious placeholders inside the secret itself
                #   — kept narrow so real-looking keys (e.g. AKIAIOSFODNN7EXAMPLE)
                #     still get flagged.
                # Tier 2 (line): the surrounding line reads like a test fixture,
                #   env-var lookup, or config template.
                captured = match.group(match.lastindex) if match.lastindex else ""
                if any(re.search(v, captured, re.IGNORECASE)
                       for v in SECRET_VALUE_ALLOWLIST):
                    continue
                if any(re.search(a, line, re.IGNORECASE)
                       for a in SECRET_LINE_ALLOWLIST):
                    continue
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.CRITICAL,
                    category="Secret Exposure",
                    message="Possible {} detected".format(label.lower()),
                    file=current_file,
                    line=i,
                    suggestion="Remove hardcoded secret. Use environment variables or a secrets manager.",
                    blocker=Blocker.BLOCKS,
                    confidence=0.85,
                    rule_id=rule_id,
                ))

            for pattern, label, rule_id in DANGEROUS_PATTERNS:
                if rule_id == "SECU-206-SAFE":
                    continue  # positive match, not a finding
                if re.search(pattern, line, re.IGNORECASE):
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.HIGH,
                        category="Dangerous Pattern",
                        message=label,
                        file=current_file,
                        line=i,
                        suggestion="Review this pattern for security risks.",
                        blocker=Blocker.BLOCKS,
                        confidence=0.80,
                        rule_id=rule_id,
                    ))

        if file_path.endswith(("package.json", "requirements.txt", "Cargo.toml", "go.mod")):
            for dep, (advice, rule_id) in INSECURE_DEPENDENCIES.items():
                if dep in content:
                    findings.append(Finding(
                        agent=self.name,
                        severity=Severity.MEDIUM,
                        category="Insecure Dependency",
                        message="Use of '{}' - {}".format(dep, advice),
                        file=current_file,
                        suggestion=advice,
                        blocker=Blocker.WARNS,
                        confidence=0.90,
                        rule_id=rule_id,
                    ))

        return findings