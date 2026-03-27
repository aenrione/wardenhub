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
class CoordinatorServerConfig:
    host: str = "0.0.0.0"
    port: int = 8080
    db_path: str = "/data/wardenhub.db"


@dataclass
class PushgatewayConfig:
    url: str = "http://pushgateway:9091"
    cleanup_threshold_seconds: int = 21600  # 6 hours


@dataclass
class ProxmoxConfig:
    host: str = ""
    verify_ssl: bool = True
    token_id: str = ""
    token_secret_file: str = ""


@dataclass
class ScheduleConfig:
    interval_seconds: int = 10800  # 3 hours


@dataclass
class CoordinatorConfig:
    coordinator: CoordinatorServerConfig = field(default_factory=CoordinatorServerConfig)
    pushgateway: PushgatewayConfig = field(default_factory=PushgatewayConfig)
    proxmox: ProxmoxConfig = field(default_factory=ProxmoxConfig)
    schedule: ScheduleConfig = field(default_factory=ScheduleConfig)


def load_config(path: str | Path) -> CoordinatorConfig:
    path = Path(path)
    if not path.exists():
        raise ConfigError(f"Config file not found: {path}")

    with path.open() as f:
        raw = yaml.safe_load(f) or {}

    coord_raw = raw.get("coordinator", {})
    coordinator = CoordinatorServerConfig(
        host=coord_raw.get("host", "0.0.0.0"),
        port=int(coord_raw.get("port", 8080)),
        db_path=coord_raw.get("db_path", "/data/wardenhub.db"),
    )

    pg_raw = raw.get("pushgateway", {})
    cleanup_threshold = pg_raw.get("cleanup_threshold", "6h")
    pushgateway = PushgatewayConfig(
        url=pg_raw.get("url", "http://pushgateway:9091"),
        cleanup_threshold_seconds=parse_duration(cleanup_threshold),
    )

    proxmox_raw = raw.get("proxmox", {})
    proxmox = ProxmoxConfig(
        host=proxmox_raw.get("host", ""),
        verify_ssl=proxmox_raw.get("verify_ssl", True),
        token_id=proxmox_raw.get("token_id", ""),
        token_secret_file=proxmox_raw.get("token_secret_file", ""),
    )

    schedule_raw = raw.get("schedule", {})
    schedule = ScheduleConfig(
        interval_seconds=parse_duration(schedule_raw.get("interval", "3h")),
    )

    return CoordinatorConfig(
        coordinator=coordinator,
        pushgateway=pushgateway,
        proxmox=proxmox,
        schedule=schedule,
    )
