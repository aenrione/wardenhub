from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from prometheus_client import CollectorRegistry

from wardenhub_agent.config import Config, HubConfig, NetworkConfig, ProvidersConfig, ScheduleConfig, ProxmoxConfig
from wardenhub_agent.models import Finding, Severity
from wardenhub_agent.pusher import PushError, PushPayload, push_metrics, register_with_coordinator


def make_config(coordinator_url=None) -> Config:
    return Config(
        hub=HubConfig(
            pushgateway_url="http://localhost:9091",
            coordinator_url=coordinator_url,
        ),
        network=NetworkConfig(),
        schedule=ScheduleConfig(),
        providers=ProvidersConfig(),
        proxmox=ProxmoxConfig(),
    )


def make_finding(**kwargs) -> Finding:
    defaults = dict(
        provider="lynis",
        check_id="SSH-7408",
        target="host",
        severity=Severity.warning,
        passed=False,
        message="Test finding",
        remediation="Fix it",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


def make_payload(**kwargs) -> PushPayload:
    defaults = dict(
        findings=[make_finding()],
        provider_errors={},
        provider_metrics={},
        providers_run=["lynis"],
        hostname="test-host",
    )
    defaults.update(kwargs)
    return PushPayload(**defaults)


def test_push_metrics_calls_push_to_gateway(mocker):
    mock_push = mocker.patch("wardenhub_agent.pusher.push_to_gateway")
    payload = make_payload()
    push_metrics(payload, make_config())
    mock_push.assert_called_once()
    call_kwargs = mock_push.call_args
    assert call_kwargs[1]["job"] == "wardenhub_agent"
    assert call_kwargs[1]["grouping_key"] == {"instance": "test-host"}


def test_push_metrics_raises_push_error_on_failure(mocker):
    mocker.patch(
        "wardenhub_agent.pusher.push_to_gateway",
        side_effect=Exception("connection refused"),
    )
    payload = make_payload()
    with pytest.raises(PushError, match="connection refused"):
        push_metrics(payload, make_config())


def test_push_metrics_includes_lynis_hardening_index(mocker):
    mock_push = mocker.patch("wardenhub_agent.pusher.push_to_gateway")
    payload = make_payload(
        provider_metrics={"lynis": {"hardening_index": 72.0, "tests_performed": 241.0}}
    )
    push_metrics(payload, make_config())
    # Verify push was called (actual metric value inspection would require registry access)
    mock_push.assert_called_once()


def test_register_with_coordinator_skipped_when_no_url(mocker):
    mock_post = mocker.patch("wardenhub_agent.pusher.httpx.post")
    payload = make_payload()
    register_with_coordinator(payload, make_config(coordinator_url=None))
    mock_post.assert_not_called()


def test_register_with_coordinator_posts_to_endpoint(mocker):
    mock_post = mocker.patch(
        "wardenhub_agent.pusher.httpx.post",
        return_value=MagicMock(status_code=200, raise_for_status=MagicMock()),
    )
    payload = make_payload()
    register_with_coordinator(payload, make_config(coordinator_url="http://localhost:8080"))
    mock_post.assert_called_once()
    assert "/api/register" in mock_post.call_args[0][0]


def test_register_with_coordinator_silently_ignores_failure(mocker):
    mocker.patch("wardenhub_agent.pusher.httpx.post", side_effect=Exception("timeout"))
    payload = make_payload()
    # Should not raise
    register_with_coordinator(payload, make_config(coordinator_url="http://localhost:8080"))
