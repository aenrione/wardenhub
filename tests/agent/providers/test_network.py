from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest

from wardenhub_agent.config import Config, HubConfig, NetworkConfig, ProvidersConfig, ScheduleConfig, ProxmoxConfig
from wardenhub_agent.models import Severity
from wardenhub_agent.providers.network import NetworkProvider


def make_config(expected_ports=None) -> Config:
    return Config(
        hub=HubConfig(pushgateway_url="http://localhost:9091"),
        network=NetworkConfig(expected_ports=expected_ports or []),
        schedule=ScheduleConfig(),
        providers=ProvidersConfig(),
        proxmox=ProxmoxConfig(),
    )


@pytest.fixture
def provider(ss_output_clean, mocker) -> NetworkProvider:
    mocker.patch(
        "wardenhub_agent.providers.network.subprocess.run",
        return_value=MagicMock(returncode=0, stdout=ss_output_clean, stderr=""),
    )
    return NetworkProvider(config=make_config(expected_ports=[22]))


def test_detect_always_true():
    assert NetworkProvider.detect() is True


def test_no_unexpected_ports(ss_output_clean, mocker):
    mocker.patch(
        "wardenhub_agent.providers.network.subprocess.run",
        return_value=MagicMock(returncode=0, stdout=ss_output_clean, stderr=""),
    )
    mocker.patch(
        "wardenhub_agent.providers.network.SSHD_CONFIG_PATH",
        Path("/nonexistent/sshd_config"),
    )
    p = NetworkProvider(config=make_config(expected_ports=[22]))
    findings = p.audit()
    open_port_findings = [f for f in findings if f.check_id == "net_open_ports"]
    assert len(open_port_findings) == 0


def test_unexpected_port_flagged(ss_output_clean, mocker):
    mocker.patch(
        "wardenhub_agent.providers.network.subprocess.run",
        return_value=MagicMock(returncode=0, stdout=ss_output_clean, stderr=""),
    )
    mocker.patch(
        "wardenhub_agent.providers.network.SSHD_CONFIG_PATH",
        Path("/nonexistent/sshd_config"),
    )
    # Port 22 is open but NOT in expected_ports
    p = NetworkProvider(config=make_config(expected_ports=[]))
    findings = p.audit()
    open_port_findings = [f for f in findings if f.check_id == "net_open_ports"]
    assert len(open_port_findings) == 1
    assert open_port_findings[0].severity == Severity.warning


def test_management_port_exposed_is_critical(ss_output_with_mgmt, mocker):
    mocker.patch(
        "wardenhub_agent.providers.network.subprocess.run",
        return_value=MagicMock(returncode=0, stdout=ss_output_with_mgmt, stderr=""),
    )
    mocker.patch(
        "wardenhub_agent.providers.network.SSHD_CONFIG_PATH",
        Path("/nonexistent/sshd_config"),
    )
    p = NetworkProvider(config=make_config(expected_ports=[22]))
    findings = p.audit()
    critical_findings = [f for f in findings if f.check_id == "net_exposed_services"]
    assert len(critical_findings) == 2  # 8006 and 2375
    assert all(f.severity == Severity.critical for f in critical_findings)


def test_loopback_port_not_flagged(ss_output_clean, mocker):
    """Port 631 is on 127.0.0.1 - should NOT be flagged as unexpected."""
    mocker.patch(
        "wardenhub_agent.providers.network.subprocess.run",
        return_value=MagicMock(returncode=0, stdout=ss_output_clean, stderr=""),
    )
    mocker.patch(
        "wardenhub_agent.providers.network.SSHD_CONFIG_PATH",
        Path("/nonexistent/sshd_config"),
    )
    p = NetworkProvider(config=make_config(expected_ports=[22]))
    findings = p.audit()
    # port 631 on 127.0.0.1 should be ignored
    port_631 = [f for f in findings if "631" in f.target]
    assert len(port_631) == 0


def test_ssh_root_login_flagged(sshd_config_root_login, tmp_path, mocker):
    sshd_path = tmp_path / "sshd_config"
    sshd_path.write_text(sshd_config_root_login)

    mocker.patch(
        "wardenhub_agent.providers.network.subprocess.run",
        return_value=MagicMock(returncode=0, stdout="Netid State\n", stderr=""),
    )
    mocker.patch("wardenhub_agent.providers.network.SSHD_CONFIG_PATH", sshd_path)

    p = NetworkProvider(config=make_config())
    findings = p.audit()
    root_login_findings = [f for f in findings if f.check_id == "net_ssh_root_login"]
    assert len(root_login_findings) == 1
    assert root_login_findings[0].severity == Severity.warning


def test_ssh_password_auth_flagged(sshd_config_root_login, tmp_path, mocker):
    sshd_path = tmp_path / "sshd_config"
    sshd_path.write_text(sshd_config_root_login)

    mocker.patch(
        "wardenhub_agent.providers.network.subprocess.run",
        return_value=MagicMock(returncode=0, stdout="Netid State\n", stderr=""),
    )
    mocker.patch("wardenhub_agent.providers.network.SSHD_CONFIG_PATH", sshd_path)

    p = NetworkProvider(config=make_config())
    findings = p.audit()
    pw_findings = [f for f in findings if f.check_id == "net_ssh_password_auth"]
    assert len(pw_findings) == 1


def test_ssh_hardened_no_findings(sshd_config_hardened, tmp_path, mocker):
    sshd_path = tmp_path / "sshd_config"
    sshd_path.write_text(sshd_config_hardened)

    mocker.patch(
        "wardenhub_agent.providers.network.subprocess.run",
        return_value=MagicMock(returncode=0, stdout="Netid State\n", stderr=""),
    )
    mocker.patch("wardenhub_agent.providers.network.SSHD_CONFIG_PATH", sshd_path)

    p = NetworkProvider(config=make_config(expected_ports=[22]))
    findings = p.audit()
    ssh_findings = [
        f for f in findings if f.check_id in ("net_ssh_root_login", "net_ssh_password_auth")
    ]
    assert len(ssh_findings) == 0
