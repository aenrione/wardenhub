from __future__ import annotations

from pathlib import Path

import pytest

FIXTURES_DIR = Path(__file__).parent / "fixtures"


@pytest.fixture
def lynis_report_sample() -> str:
    return (FIXTURES_DIR / "lynis_report_sample.dat").read_text()


@pytest.fixture
def sshd_config_hardened() -> str:
    return (FIXTURES_DIR / "sshd_config_hardened.txt").read_text()


@pytest.fixture
def sshd_config_root_login() -> str:
    return (FIXTURES_DIR / "sshd_config_root_login.txt").read_text()


@pytest.fixture
def ss_output_clean() -> str:
    return (FIXTURES_DIR / "ss_output_clean.txt").read_text()


@pytest.fixture
def ss_output_with_mgmt() -> str:
    return (FIXTURES_DIR / "ss_output_with_mgmt.txt").read_text()
