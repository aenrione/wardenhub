from __future__ import annotations

import subprocess
from pathlib import Path

import structlog

from wardenhub_agent.config import Config
from wardenhub_agent.models import Finding, Severity
from wardenhub_agent.providers.base import BaseProvider

log = structlog.get_logger()

MANAGEMENT_PORTS = {8006, 2375, 2376, 5900, 6080}
SSHD_CONFIG_PATH = Path("/etc/ssh/sshd_config")


class NetworkProvider(BaseProvider):
    id = "network"
    name = "Network"

    def __init__(self, config: Config | None = None) -> None:
        self._config = config

    @classmethod
    def detect(cls) -> bool:
        return True

    def audit(self) -> list[Finding]:
        findings: list[Finding] = []
        open_ports = self._get_open_ports()

        findings.extend(self._check_open_ports(open_ports))
        findings.extend(self._check_exposed_services(open_ports))
        findings.extend(self._check_firewall())
        findings.extend(self._check_ssh_config())

        return findings

    def _get_open_ports(self) -> list[dict]:
        """Run ss and return list of {port, addr} dicts for listening TCP sockets."""
        try:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as e:
            log.warning("ss command failed", error=str(e))
            return []

        ports = []
        lines = result.stdout.splitlines()
        # Skip header line
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 5:
                continue
            local_addr = parts[4]  # e.g. "0.0.0.0:22" or ":::22"
            try:
                port = int(local_addr.rsplit(":", 1)[-1])
                addr = local_addr.rsplit(":", 1)[0]
                ports.append({"port": port, "addr": addr})
            except (ValueError, IndexError):
                continue

        return ports

    def _is_non_loopback(self, addr: str) -> bool:
        """Return True if the address is not loopback-only."""
        loopback = {"127.0.0.1", "::1", "[::1]"}
        return addr not in loopback

    def _check_open_ports(self, open_ports: list[dict]) -> list[Finding]:
        findings = []
        expected = set(self._config.network.expected_ports) if self._config else set()
        seen_ports = set()

        for entry in open_ports:
            port = entry["port"]
            addr = entry["addr"]
            if port in seen_ports:
                continue
            seen_ports.add(port)

            if port not in expected and self._is_non_loopback(addr):
                findings.append(
                    Finding(
                        provider=self.id,
                        check_id="net_open_ports",
                        target=f"port/{port}",
                        severity=Severity.warning,
                        passed=False,
                        message=f"Unexpected open port {port} on {addr}",
                        remediation=(
                            f"Close port {port} if not needed, or add it to "
                            "network.expected_ports in agent config."
                        ),
                    )
                )

        return findings

    def _check_exposed_services(self, open_ports: list[dict]) -> list[Finding]:
        findings = []
        for entry in open_ports:
            port = entry["port"]
            addr = entry["addr"]
            if port in MANAGEMENT_PORTS and self._is_non_loopback(addr):
                findings.append(
                    Finding(
                        provider=self.id,
                        check_id="net_exposed_services",
                        target=f"port/{port}",
                        severity=Severity.critical,
                        passed=False,
                        message=f"Management service on port {port} exposed on {addr}",
                        remediation=(
                            f"Bind port {port} to a specific interface or restrict access "
                            "with firewall rules."
                        ),
                    )
                )
        return findings

    def _check_firewall(self) -> list[Finding]:
        active = self._iptables_active() or self._nftables_active()
        if not active:
            return [
                Finding(
                    provider=self.id,
                    check_id="net_firewall_active",
                    target="host",
                    severity=Severity.warning,
                    passed=False,
                    message="No active firewall detected (iptables or nftables)",
                    remediation="Enable and configure iptables or nftables to restrict inbound traffic.",
                )
            ]
        return []

    def _iptables_active(self) -> bool:
        try:
            result = subprocess.run(
                ["iptables", "-L", "-n"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return False
            lines = [l for l in result.stdout.splitlines() if l.strip()]
            # Default iptables output has 3 chains with "policy ACCEPT" and nothing else
            # If there are more lines, rules exist
            return len(lines) > 6
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _nftables_active(self) -> bool:
        try:
            result = subprocess.run(
                ["nft", "list", "ruleset"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            return result.returncode == 0 and bool(result.stdout.strip())
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _check_ssh_config(self) -> list[Finding]:
        findings = []
        if not SSHD_CONFIG_PATH.exists():
            return findings

        content = SSHD_CONFIG_PATH.read_text()
        lines = [
            line.strip()
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

        root_login = None
        password_auth = None

        for line in lines:
            parts = line.split()
            if len(parts) < 2:
                continue
            key = parts[0].lower()
            value = parts[1].lower()
            if key == "permitrootlogin":
                root_login = value
            elif key == "passwordauthentication":
                password_auth = value

        if root_login in ("yes", "without-password"):
            findings.append(
                Finding(
                    provider=self.id,
                    check_id="net_ssh_root_login",
                    target="host",
                    severity=Severity.warning,
                    passed=False,
                    message=f"SSH allows root login (PermitRootLogin={root_login})",
                    remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and restart sshd.",
                )
            )

        if password_auth == "yes":
            findings.append(
                Finding(
                    provider=self.id,
                    check_id="net_ssh_password_auth",
                    target="host",
                    severity=Severity.warning,
                    passed=False,
                    message="SSH allows password authentication",
                    remediation=(
                        "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config "
                        "and restart sshd. Use SSH keys instead."
                    ),
                )
            )

        return findings
