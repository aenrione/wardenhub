from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    critical = "critical"
    warning = "warning"
    info = "info"


@dataclass(frozen=True, slots=True)
class Finding:
    provider: str
    check_id: str
    target: str
    severity: Severity
    passed: bool
    message: str
    remediation: str

    def __post_init__(self) -> None:
        # Truncate label values at 128 chars for Prometheus compatibility
        object.__setattr__(self, "message", self.message[:128])
        object.__setattr__(self, "remediation", self.remediation[:128])
