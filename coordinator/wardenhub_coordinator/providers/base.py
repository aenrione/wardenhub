from __future__ import annotations

from abc import ABC, abstractmethod


class BaseCoordinatorProvider(ABC):
    id: str
    name: str

    @classmethod
    @abstractmethod
    def detect(cls) -> bool:
        """Return True if this provider is configured and available."""

    @abstractmethod
    def audit(self) -> list:
        """Run cluster-level checks and return findings."""
