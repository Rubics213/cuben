"""
models.py — Shared dataclasses used across active_tests, credential_harvester, active_main
"""
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class SessionConfig:
    """Credentials for one account."""
    name: str
    auth_header: str = ""      # e.g. "Bearer eyJ..."
    cookie: str = ""           # e.g. "SESSION=ABC..."
    org_id: str = ""           # e.g. Coveo org ID
    source_host: str = ""      # host where credentials were found


@dataclass
class ActiveFinding:
    test_type: str          # "IDOR" | "BROKEN_AUTH" | "WEAK_AUTH"
    severity: str           # CRITICAL / HIGH / MEDIUM
    endpoint: str
    method: str
    description: str
    evidence: str
    request_a: str = ""
    request_b: str = ""
    response_a: str = ""
    response_b: str = ""
    status_a: int = 0
    status_b: int = 0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())

    def is_high_priority(self) -> bool:
        return self.severity in ("CRITICAL", "HIGH")


@dataclass
class ActiveTestRun:
    target: str
    started_at: str = field(default_factory=lambda: datetime.now().isoformat())
    idor_findings: list[ActiveFinding] = field(default_factory=list)
    auth_findings: list[ActiveFinding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    tested_count: int = 0
