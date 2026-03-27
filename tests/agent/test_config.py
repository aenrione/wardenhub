from __future__ import annotations

import pytest

from wardenhub_agent.config import ConfigError, load_config, parse_duration


def test_parse_duration_hours():
    assert parse_duration("3h") == 10800


def test_parse_duration_minutes():
    assert parse_duration("30m") == 1800


def test_parse_duration_seconds():
    assert parse_duration("90s") == 90


def test_parse_duration_days():
    assert parse_duration("1d") == 86400


def test_parse_duration_invalid():
    with pytest.raises(ConfigError):
        parse_duration("3x")


def test_load_config_minimal(tmp_path):
    config_file = tmp_path / "agent.yaml"
    config_file.write_text("hub:\n  pushgateway_url: http://localhost:9091\n")
    cfg = load_config(config_file)
    assert cfg.hub.pushgateway_url == "http://localhost:9091"
    assert cfg.hub.coordinator_url is None


def test_load_config_with_coordinator(tmp_path):
    config_file = tmp_path / "agent.yaml"
    config_file.write_text(
        "hub:\n"
        "  pushgateway_url: http://localhost:9091\n"
        "  coordinator_url: http://localhost:8080\n"
    )
    cfg = load_config(config_file)
    assert cfg.hub.coordinator_url == "http://localhost:8080"


def test_load_config_missing_pushgateway(tmp_path):
    config_file = tmp_path / "agent.yaml"
    config_file.write_text("hub:\n  coordinator_url: http://localhost:8080\n")
    with pytest.raises(ConfigError, match="pushgateway_url"):
        load_config(config_file)


def test_load_config_enabled_and_disabled_raises(tmp_path):
    config_file = tmp_path / "agent.yaml"
    config_file.write_text(
        "hub:\n"
        "  pushgateway_url: http://localhost:9091\n"
        "providers:\n"
        "  enabled: [lynis]\n"
        "  disabled: [network]\n"
    )
    with pytest.raises(ConfigError, match="cannot both be set"):
        load_config(config_file)


def test_load_config_missing_file():
    with pytest.raises(ConfigError, match="not found"):
        load_config("/nonexistent/agent.yaml")


def test_load_config_schedule_interval(tmp_path):
    config_file = tmp_path / "agent.yaml"
    config_file.write_text(
        "hub:\n"
        "  pushgateway_url: http://localhost:9091\n"
        "schedule:\n"
        "  interval: 1h\n"
    )
    cfg = load_config(config_file)
    assert cfg.schedule.interval_seconds == 3600
