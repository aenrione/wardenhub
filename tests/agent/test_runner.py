from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from wardenhub_agent.config import Config, ConfigError, HubConfig, NetworkConfig, ProvidersConfig, ScheduleConfig, ProxmoxConfig
from wardenhub_agent.models import Finding, Severity
from wardenhub_agent.runner import RunResult, _select_providers, run_once


def make_config(**kwargs) -> Config:
    providers = kwargs.pop("providers", ProvidersConfig())
    return Config(
        hub=HubConfig(pushgateway_url="http://localhost:9091"),
        providers=providers,
        network=NetworkConfig(expected_ports=[22]),
        schedule=ScheduleConfig(),
        proxmox=ProxmoxConfig(),
        **kwargs,
    )


class MockProvider:
    id = "mock"
    name = "Mock"
    findings = []
    should_error = False

    @classmethod
    def detect(cls) -> bool:
        return True

    def audit(self) -> list[Finding]:
        if self.should_error:
            raise RuntimeError("mock provider error")
        return self.findings


def test_select_providers_auto_detect(mocker):
    mock_cls = MagicMock()
    mock_cls.id = "mock"
    mock_cls.detect.return_value = True
    mock_cls.return_value = MagicMock()

    mocker.patch("wardenhub_agent.runner.ALL_PROVIDERS", [mock_cls])
    cfg = make_config()
    providers = _select_providers(cfg)
    assert len(providers) == 1
    mock_cls.detect.assert_called_once()


def test_select_providers_enabled_list_skips_detect(mocker):
    mock_cls = MagicMock()
    mock_cls.id = "lynis"
    mock_cls.return_value = MagicMock()

    mocker.patch("wardenhub_agent.runner.ALL_PROVIDERS", [mock_cls])
    cfg = make_config(providers=ProvidersConfig(enabled=["lynis"]))
    providers = _select_providers(cfg)
    assert len(providers) == 1
    mock_cls.detect.assert_not_called()


def test_select_providers_disabled_list(mocker):
    mock_cls = MagicMock()
    mock_cls.id = "lynis"
    mock_cls.detect.return_value = True

    mocker.patch("wardenhub_agent.runner.ALL_PROVIDERS", [mock_cls])
    cfg = make_config(providers=ProvidersConfig(disabled=["lynis"]))
    providers = _select_providers(cfg)
    assert len(providers) == 0


def test_select_providers_not_in_enabled_list(mocker):
    mock_cls = MagicMock()
    mock_cls.id = "lynis"

    mocker.patch("wardenhub_agent.runner.ALL_PROVIDERS", [mock_cls])
    cfg = make_config(providers=ProvidersConfig(enabled=["network"]))
    providers = _select_providers(cfg)
    assert len(providers) == 0


def test_provider_detect_exception_is_skipped(mocker):
    mock_cls = MagicMock()
    mock_cls.id = "mock"
    mock_cls.detect.side_effect = RuntimeError("detect failed")

    mocker.patch("wardenhub_agent.runner.ALL_PROVIDERS", [mock_cls])
    cfg = make_config()
    providers = _select_providers(cfg)
    assert len(providers) == 0


def test_provider_audit_exception_sets_error(mocker):
    mock_provider = MagicMock()
    mock_provider.id = "mock"
    mock_provider.audit.side_effect = RuntimeError("audit failed")

    mock_cls = MagicMock()
    mock_cls.id = "mock"
    mock_cls.detect.return_value = True
    mock_cls.return_value = mock_provider

    mocker.patch("wardenhub_agent.runner.ALL_PROVIDERS", [mock_cls])
    mocker.patch("wardenhub_agent.runner.push_metrics")
    mocker.patch("wardenhub_agent.runner.register_with_coordinator")

    cfg = make_config()
    result = run_once(cfg)
    assert result.provider_errors.get("mock") is True
    assert len(result.findings) == 0
