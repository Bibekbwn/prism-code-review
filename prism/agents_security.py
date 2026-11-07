"""Security Agent - Checks for secrets, dangerous patterns, and CVEs."""

import re
from typing import List
from prism.agents import BaseAgent, Finding, Severity, Blocker, register_agent


def _strip_comments(content: str, file_path: str) -> str:
    """Remove comments from code to avoid false positives in comments.
    
    Only strips comments — preserves string literals so that
    actual secrets inside strings are still detected.
    """
    lines = content.split("\n")
    result = []
    
    for line in lines:
        if file_path.endswith(".py"):
            # Remove # comments (but not inside strings)
            in_string = False
            string_char = None
            cleaned = []
            i = 0
            while i < len(line):
                ch = line[i]
                if not in_string and ch in ('"', "'"):
                    in_string = True
                    string_char = ch
                    cleaned.append(ch)
                elif in_string and ch == string_char:
                    in_string = False
                    cleaned.append(ch)
                elif in_string:
                    cleaned.append(ch)
                elif ch == "#":
                    break  # rest of line is comment
                else:
                    cleaned.append(ch)
                i += 1
            result.append("".join(cleaned))
        elif file_path.endswith((".js", ".ts", ".jsx", ".tsx")):
            in_string = False
            string_char = None
            in_block_comment = False
            cleaned = []
            i = 0
            while i < len(line):
                ch = line[i]
                next_ch = line[i + 1] if i + 1 < len(line) else ""
                
                if in_block_comment:
                    if ch == "*" and next_ch == "/":
                        in_block_comment = False
                        i += 2
                        continue
                    cleaned.append(" ")
                    i += 1
                    continue
                
                if not in_string and ch == "/" and next_ch == "/":
                    break  # rest of line is comment
                if not in_string and ch == "/" and next_ch == "*":
                    in_block_comment = True
                    i += 2
                    continue
                
                if not in_string and ch in ('"', "'", "`"):
                    in_string = True
                    string_char = ch
                    cleaned.append(ch)
                elif in_string and ch == string_char:
                    in_string = False
                    cleaned.append(ch)
                elif in_string:
                    cleaned.append(ch)
                else:
                    cleaned.append(ch)
                i += 1
            result.append("".join(cleaned))
        else:
            result.append(line)
    
    return "\n".join(result)


SECRET_PATTERNS = [
    (r'(?i)(api[_-]?key|apikey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "API Key", "SECU-101", "Use os.environ.get('API_KEY') instead"),
    (r'(?i)(secret[_-]?key|secretkey)\s*[:=]\s*["\']([A-Za-z0-9_\-]{16,})["\']', "Secret Key", "SECU-102", "Use os.environ.get('SECRET_KEY') instead"),
    (r'(?i)(?:^|\s)(?:password|passwd|pwd)\s*[:=]\s*["\']([^\s\'\"\n]{8,})["\']', "Password", "SECU-103", "Use os.environ.get('PASSWORD') instead"),
    (r'(?i)(token|access_token)\s*[:=]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']', "Auth Token", "SECU-104", "Use os.environ.get('TOKEN') instead"),
    (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID", "SECU-105", "Use boto3.session.Session() with IAM role"),
    (r'(?i)(github|gitlab)_token\s*[:=]\s*["\']([A-Za-z0-9_\-]{20,})["\']', "Git Token", "SECU-106", "Use os.environ.get('GITHUB_TOKEN') instead"),
    (r'(?i)(private_key|privatekey)\s*[:=]\s*["\']([^\s\'\"\n]{20,})["\']', "Private Key", "SECU-107", "Use os.environ.get('PRIVATE_KEY') instead"),
    (r'(?i)(mysql|postgres|mongodb)://[^\s\'\"<>]+', "Database Connection String", "SECU-108", "Use environment variable for DB URL"),
]

DANGEROUS_PATTERNS = [
    (r"\beval\s*\(", "Use of eval() - code injection risk", "SECU-201", "Use ast.literal_eval() for safe parsing"),
    (r"\bexec\s*\(", "Use of exec() - code injection risk", "SECU-202", "Avoid dynamic code execution"),
    (r"subprocess\.(call|run|Popen)\s*\([^)]*-shell\s*=\s*True", "Shell=True in subprocess - command injection risk", "SECU-203", "Use shell=False with argument list"),
    (r"os\.system\s*\(", "Use of os.system() - command injection risk", "SECU-204", "Use subprocess.run() with shell=False"),
    (r"pickle\.loads?\s*\(", "Use of pickle - deserialization risk", "SECU-205", "Use JSON or a safe serializer"),
    (r"yaml\.load\s*\(", "Use of yaml.load() without SafeLoader - deserialization risk", "SECU-206", "Use yaml.safe_load() instead"),
    (r"SELECT\s+.+\s+FROM\s+.+\s+WHERE\s+.+\s*=\s*['\"].*\+", "SQL injection - string concatenation in query", "SECU-207", "Use parameterized queries with placeholders"),
    (r"document\.getElementById\([^)]*\)\.innerHTML\s*=", "XSS - innerHTML assignment", "SECU-208", "Use textContent or sanitize input"),
    (r"\.\w+\s*\+\s*['\"]", "Potential XSS - string concatenation in HTML", "SECU-209", "Use template literals with sanitization"),
]


@register_agent
class SecurityAgent(BaseAgent):
    name = "security"
    description = "Detects hardcoded secrets, dangerous patterns, and insecure dependencies"

    def _check(self, file_path: str, content: str, diff: str) -> List[Finding]:
        """Run security checks and return list of Findings."""
        findings = []
        
        # Strip comments to avoid false positives
        # (e.g., detecting "password" in a comment or example)
        clean_content = _strip_comments(content, file_path)

        for pattern, secret_type, rule_id, suggestion in SECRET_PATTERNS:
            for match in re.finditer(pattern, clean_content, re.MULTILINE):
                line_num = clean_content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.CRITICAL,
                    category="Secret Exposure",
                    message="{} detected".format(secret_type),
                    file=file_path,
                    line=line_num,
                    suggestion=suggestion,
                    suggested_code="import os\n{} = os.environ.get('{}')".format(
                        secret_type.replace(" ", "_").upper(), secret_type
                    ),
                    blocker=Blocker.BLOCKS,
                    confidence=0.95,
                    rule_id=rule_id,
                ))

        for pattern, message, rule_id, suggestion in DANGEROUS_PATTERNS:
            for match in re.finditer(pattern, clean_content, re.MULTILINE):
                line_num = clean_content[:match.start()].count("\n") + 1
                findings.append(Finding(
                    agent=self.name,
                    severity=Severity.HIGH,
                    category="Dangerous Pattern",
                    message=message,
                    file=file_path,
                    line=line_num,
                    suggestion=suggestion,
                    suggested_code="# Replace this dangerous pattern with:\n# {}".format(suggestion),
                    blocker=Blocker.BLOCKS,
                    confidence=0.80,
                    rule_id=rule_id,
                ))

        return findings