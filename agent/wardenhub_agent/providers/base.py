from __future__ import annotations

from abc import ABC, abstractmethod

from wardenhub_agent.models import Finding


class BaseProvider(ABC):
    id: str
    name: str

    @classmethod
    @abstractmethod
    def detect(cls) -> bool:
        """Return True if this provider can run on this host."""

    @abstractmethod
    def audit(self) -> list[Finding]:
        """Run all checks and return findings."""


class BaseCheck(ABC):
    """Base class for custom checks within an existing provider (Phase 4)."""

    id: str
    provider: str

    @abstractmethod
    def evaluate(self, context: dict) -> list[Finding]:
        """Evaluate the check and return findings."""
