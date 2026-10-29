"""Language-agnostic regex rules. Add a tuple to RULES to extend."""
from __future__ import annotations
import re
from ..models import Finding, Severity as S
from ..registry import code_check

# (id, title, severity, cwe, owasp, regex, extensions or None, fix, mask_evidence)
RULES = [
    ("GEN-SEC-001", "AWS access key ID", S.HIGH, "CWE-798", "A07:2021",
     r"\bAKIA[0-9A-Z]{16}\b", None, "Rotate the key; use a secrets manager.", True),
    ("GEN-SEC-002", "Private key in source", S.CRITICAL, "CWE-321", "A02:2021",
     r"-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", None,
     "Remove and rotate the key.", True),
    ("GEN-SEC-003", "Hard-coded credential assignment", S.MEDIUM, "CWE-798", "A07:2021",
     r"(?i)\b(password|passwd|secret|api[_-]?key|token)\b\s*[:=]\s*['\"][^'\"\s]{6,}['\"]",
     (".js", ".ts", ".php", ".java", ".rb", ".go", ".env", ".yml", ".yaml", ".json", ".cfg", ".ini"),
     "Move to environment/secret store.", True),
    ("JS-XSS-001", "innerHTML / document.write sink", S.MEDIUM, "CWE-79", "A03:2021",
     r"\.innerHTML\s*=|document\.write\(", (".js", ".ts", ".jsx", ".tsx", ".html"),
     "Use textContent or a sanitiser (DOMPurify).", False),
    ("JS-INJ-001", "eval() usage", S.HIGH, "CWE-95", "A03:2021",
     r"\beval\s*\(", (".js", ".ts", ".jsx", ".tsx"), "Remove eval; parse data explicitly.", False),
    ("PHP-INJ-001", "User input in dangerous PHP function", S.HIGH, "CWE-94", "A03:2021",
     r"\b(eval|system|shell_exec|exec|passthru|popen)\s*\([^;]*\$_(GET|POST|REQUEST|COOKIE)",
     (".php",), "Validate/escape input; avoid shell calls.", False),
    ("PHP-SQLI-001", "User input concatenated into SQL (PHP)", S.HIGH, "CWE-89", "A03:2021",
     r"(?i)(mysqli?_query|->query)\s*\([^;]*\$_(GET|POST|REQUEST)", (".php",),
     "Use prepared statements (PDO/mysqli).", False),
    ("JAVA-CMD-001", "Runtime.exec call", S.MEDIUM, "CWE-78", "A03:2021",
     r"Runtime\.getRuntime\(\)\.exec\(", (".java",), "Avoid shell; validate arguments.", False),
    ("JAVA-CRY-001", "Weak hash (MD5/SHA-1)", S.MEDIUM, "CWE-327", "A02:2021",
     r"MessageDigest\.getInstance\(\s*\"(MD5|SHA-?1)\"", (".java",), "Use SHA-256+.", False),
    ("GEN-CRY-002", "Weak hash MD5/SHA1 call", S.LOW, "CWE-327", "A02:2021",
     r"(?i)\b(md5|sha1)\s*\(", (".js", ".php", ".go", ".rb"), "Use SHA-256+; bcrypt/argon2.", False),
]
COMPILED = [(r[:5] + (re.compile(r[5]),) + r[6:]) for r in RULES]


def _mask(s):
    s = s.strip()
    return (s[:6] + "…[redacted]") if len(s) > 6 else "[redacted]"


@code_check
def regex_rules(path, text):
    ext = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    out = []
    for lineno, line in enumerate(text.splitlines(), 1):
        if len(line) > 2000:
            continue
        for rid, title, sev, cwe, owasp, rx, exts, fix, mask in COMPILED:
            if exts and ext not in exts:
                continue
            m = rx.search(line)
            if m:
                ev = _mask(m.group(0)) if mask else line.strip()[:120]
                out.append(Finding(rid, title, sev, "code", path, "", fix, cwe, owasp, lineno, ev))
    return out
