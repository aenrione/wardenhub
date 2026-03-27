from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from wardenhub_agent.models import Severity
from wardenhub_agent.providers.lynis import LynisProvider, ProviderError


@pytest.fixture
def provider() -> LynisProvider:
    return LynisProvider()


def test_detect_when_lynis_present(mocker):
    mocker.patch("shutil.which", return_value="/usr/bin/lynis")
    assert LynisProvider.detect() is True


def test_detect_when_lynis_absent(mocker):
    mocker.patch("shutil.which", return_value=None)
    assert LynisProvider.detect() is False


def test_parse_report_warnings_and_suggestions(provider, lynis_report_sample, tmp_path, mocker):
    report_file = tmp_path / "lynis-report.dat"
    report_file.write_text(lynis_report_sample)

    mocker.patch("wardenhub_agent.providers.lynis.REPORT_PATH", report_file)
    mocker.patch(
        "wardenhub_agent.providers.lynis.subprocess.run",
        return_value=MagicMock(returncode=1, stderr=""),
    )

    findings = provider.audit()

    warnings = [f for f in findings if f.severity == Severity.warning]
    suggestions = [f for f in findings if f.severity == Severity.info]

    assert len(warnings) == 2
    assert len(suggestions) == 3
    assert provider.hardening_index == 72
    assert provider.tests_performed == 241


def test_parse_report_check_ids(provider, lynis_report_sample, tmp_path, mocker):
    report_file = tmp_path / "lynis-report.dat"
    report_file.write_text(lynis_report_sample)

    mocker.patch("wardenhub_agent.providers.lynis.REPORT_PATH", report_file)
    mocker.patch(
        "wardenhub_agent.providers.lynis.subprocess.run",
        return_value=MagicMock(returncode=1, stderr=""),
    )

    findings = provider.audit()
    check_ids = {f.check_id for f in findings}

    assert "SSH-7408" in check_ids
    assert "FILE_PERMISSIONS_UMASK" in check_ids
    assert "BOOT-5122" in check_ids


def test_lynis_exit_code_1_is_not_error(provider, lynis_report_sample, tmp_path, mocker):
    """Exit code 1 means findings present, not a Lynis error."""
    report_file = tmp_path / "lynis-report.dat"
    report_file.write_text(lynis_report_sample)

    mocker.patch("wardenhub_agent.providers.lynis.REPORT_PATH", report_file)
    mocker.patch(
        "wardenhub_agent.providers.lynis.subprocess.run",
        return_value=MagicMock(returncode=1, stderr=""),
    )

    # Should not raise
    findings = provider.audit()
    assert len(findings) > 0


def test_lynis_exit_code_2_raises(provider, mocker):
    """Exit code 2+ is a real Lynis error."""
    mocker.patch(
        "wardenhub_agent.providers.lynis.subprocess.run",
        return_value=MagicMock(returncode=2, stderr="permission denied"),
    )
    with pytest.raises(ProviderError, match="Lynis exited with code 2"):
        provider.audit()


def test_stale_report_raises(provider, lynis_report_sample, tmp_path, mocker):
    report_file = tmp_path / "lynis-report.dat"
    report_file.write_text(lynis_report_sample)

    mocker.patch("wardenhub_agent.providers.lynis.REPORT_PATH", report_file)
    mocker.patch(
        "wardenhub_agent.providers.lynis.subprocess.run",
        return_value=MagicMock(returncode=0, stderr=""),
    )
    # Make the report appear old
    mocker.patch("wardenhub_agent.providers.lynis.time.time", return_value=time.time() + 700)

    with pytest.raises(ProviderError, match="old"):
        provider.audit()


def test_missing_report_raises(provider, mocker):
    mocker.patch(
        "wardenhub_agent.providers.lynis.subprocess.run",
        return_value=MagicMock(returncode=0, stderr=""),
    )
    mocker.patch(
        "wardenhub_agent.providers.lynis.REPORT_PATH",
        Path("/nonexistent/lynis-report.dat"),
    )

    with pytest.raises(ProviderError, match="not found"):
        provider.audit()


def test_all_findings_target_is_host(provider, lynis_report_sample, tmp_path, mocker):
    report_file = tmp_path / "lynis-report.dat"
    report_file.write_text(lynis_report_sample)

    mocker.patch("wardenhub_agent.providers.lynis.REPORT_PATH", report_file)
    mocker.patch(
        "wardenhub_agent.providers.lynis.subprocess.run",
        return_value=MagicMock(returncode=1, stderr=""),
    )

    findings = provider.audit()
    assert all(f.target == "host" for f in findings)
