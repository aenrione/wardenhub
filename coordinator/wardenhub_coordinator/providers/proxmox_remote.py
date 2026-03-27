from __future__ import annotations

"""Proxmox remote provider — Phase 3 stub."""

from wardenhub_coordinator.providers.base import BaseCoordinatorProvider


class ProxmoxRemoteProvider(BaseCoordinatorProvider):
    id = "proxmox_remote"
    name = "Proxmox (Remote)"

    @classmethod
    def detect(cls) -> bool:
        # Phase 3: return True when proxmox config is present and proxmoxer is installed
        return False

    def audit(self) -> list:
        return []
