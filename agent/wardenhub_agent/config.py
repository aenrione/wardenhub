from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

import yaml


class ConfigError(Exception):
    pass


def parse_duration(s: str) -> int:
    """Parse duration strings like '3h', '30m', '90s' into seconds."""
    match = re.fullmatch(r"(\d+)([smhd])", s.strip())
    if not match:
        raise ConfigError(f"Invalid duration format: {s!r}. Expected e.g. '3h', '30m', '90s'.")
    value, unit = int(match.group(1)), match.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]


@dataclass
class HubConfig:
    pushgateway_url: str
    coordinator_url: str | None = None


@dataclass
class ScheduleConfig:
    interval_seconds: int = 10800  # 3 hours default


@dataclass
class ProvidersConfig:
    enabled: list[str] | None = None
    disabled: list[str] = field(default_factory=list)


@dataclass
class ProxmoxConfig:
    host: str = ""
    verify_ssl: bool = True
    token_id: str = ""
    token_secret_file: str = ""


@dataclass
class NetworkConfig:
    expected_ports: list[int] = field(default_factory=list)


@dataclass
class Config:
    hub: HubConfig
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)
    providers: ProvidersConfig = field(default_factory=ProvidersConfig)
    proxmox: ProxmoxConfig = field(default_factory=ProxmoxConfig)
    network: NetworkConfig = field(default_factory=NetworkConfig)


def load_config(path: str | Path) -> Config:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    with path.open() as f:
        raw = yaml.safe_load(f) or {}

    hub_raw = raw.get("hub", {})
    if "pushgateway_url" not in hub_raw:
        raise ConfigError("hub.pushgateway_url is required in config")

    hub = HubConfig(
        pushgateway_url=hub_raw["pushgateway_url"],
        coordinator_url=hub_raw.get("coordinator_url"),
    )

    schedule = ScheduleConfig()
    if "schedule" in raw:
        interval_str = raw["schedule"].get("interval", "3h")
        schedule.interval_seconds = parse_duration(interval_str)

    providers_raw = raw.get("providers", {})
    enabled = providers_raw.get("enabled")
    disabled = providers_raw.get("disabled", [])
    if enabled is not None and disabled:
        raise ConfigError(
            "providers.enabled and providers.disabled cannot both be set. "
            "Use 'enabled' for an explicit list or 'disabled' to exclude specific providers."
        )
    providers = ProvidersConfig(enabled=enabled, disabled=disabled)

    proxmox_raw = raw.get("proxmox", {})
    proxmox = ProxmoxConfig(
        host=proxmox_raw.get("host", ""),
        verify_ssl=proxmox_raw.get("verify_ssl", True),
        token_id=proxmox_raw.get("token_id", ""),
        token_secret_file=proxmox_raw.get("token_secret_file", ""),
    )

    network_raw = raw.get("network", {})
    network = NetworkConfig(
        expected_ports=network_raw.get("expected_ports", []),
    )

    return Config(hub=hub, schedule=schedule, providers=providers, proxmox=proxmox, network=network)
