from __future__ import annotations
from dataclasses import dataclass, asdict
from enum import IntEnum
from typing import Optional


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, s: str) -> "Severity":
        return cls[s.strip().upper()]


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    kind: str                      # "web" | "code"
    location: str                  # URL or file path
    description: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    line: Optional[int] = None
    evidence: str = ""
    triage_verdict: str = ""     # true_positive | false_positive | uncertain
    triage_note: str = ""

    def key(self):
        return (self.rule_id, self.location, self.line, self.evidence)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["severity"] = self.severity.name
        return d
