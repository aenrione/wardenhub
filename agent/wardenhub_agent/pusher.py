from __future__ import annotations

import socket
import time
from dataclasses import dataclass

import httpx
import structlog
from prometheus_client import CollectorRegistry, Gauge, push_to_gateway

from wardenhub_agent.config import Config
from wardenhub_agent.models import Finding, Severity

log = structlog.get_logger()


class PushError(Exception):
    pass


@dataclass
class PushPayload:
    findings: list[Finding]
    provider_errors: dict[str, bool]
    provider_metrics: dict[str, dict[str, float]]
    providers_run: list[str]
    hostname: str | None = None


def _get_hostname() -> str:
    return socket.gethostname()


def push_metrics(payload: PushPayload, config: Config) -> None:
    hostname = payload.hostname or _get_hostname()
    registry = CollectorRegistry()

    check_result = Gauge(
        "wardenhub_check_result",
        "1=pass, 0=fail",
        ["instance", "provider", "check_id", "target", "severity"],
        registry=registry,
    )

    findings_total = Gauge(
        "wardenhub_findings_total",
        "Count of findings by severity",
        ["instance", "provider", "severity"],
        registry=registry,
    )

    last_run = Gauge(
        "wardenhub_last_run_timestamp",
        "Unix timestamp of last audit run",
        ["instance", "provider"],
        registry=registry,
    )

    provider_error = Gauge(
        "wardenhub_provider_error",
        "1 if provider errored during last run",
        ["instance", "provider"],
        registry=registry,
    )

    finding_info = Gauge(
        "wardenhub_finding_info",
        "Finding details for Grafana tables",
        ["instance", "provider", "check_id", "target", "severity", "message", "remediation"],
        registry=registry,
    )

    lynis_hardening_index = Gauge(
        "wardenhub_lynis_hardening_index",
        "Lynis hardening index score (0-100)",
        ["instance"],
        registry=registry,
    )

    lynis_tests_performed = Gauge(
        "wardenhub_lynis_tests_performed",
        "Number of tests performed by Lynis",
        ["instance"],
        registry=registry,
    )

    # Populate check results and finding info
    for finding in payload.findings:
        check_result.labels(
            instance=hostname,
            provider=finding.provider,
            check_id=finding.check_id,
            target=finding.target,
            severity=finding.severity,
        ).set(1 if finding.passed else 0)

        if not finding.passed:
            finding_info.labels(
                instance=hostname,
                provider=finding.provider,
                check_id=finding.check_id,
                target=finding.target,
                severity=finding.severity,
                message=finding.message,
                remediation=finding.remediation,
            ).set(1)

    # Aggregate findings_total by provider + severity
    counts: dict[tuple[str, str], int] = {}
    for finding in payload.findings:
        key = (finding.provider, finding.severity)
        counts[key] = counts.get(key, 0) + 1

    for (provider, severity), count in counts.items():
        findings_total.labels(
            instance=hostname, provider=provider, severity=severity
        ).set(count)

    # last_run and provider_error per provider
    now = time.time()
    for provider_id in payload.providers_run:
        last_run.labels(instance=hostname, provider=provider_id).set(now)
        provider_error.labels(instance=hostname, provider=provider_id).set(
            1 if payload.provider_errors.get(provider_id) else 0
        )

    # Lynis-specific metrics
    lynis_metrics = payload.provider_metrics.get("lynis", {})
    if "hardening_index" in lynis_metrics:
        lynis_hardening_index.labels(instance=hostname).set(lynis_metrics["hardening_index"])
    if "tests_performed" in lynis_metrics:
        lynis_tests_performed.labels(instance=hostname).set(lynis_metrics["tests_performed"])

    # Push to Pushgateway
    try:
        push_to_gateway(
            config.hub.pushgateway_url,
            job="wardenhub_agent",
            registry=registry,
            grouping_key={"instance": hostname},
        )
        log.info("metrics pushed", pushgateway=config.hub.pushgateway_url, hostname=hostname)
    except Exception as e:
        raise PushError(f"Failed to push metrics to Pushgateway: {e}") from e


def register_with_coordinator(payload: PushPayload, config: Config) -> None:
    if not config.hub.coordinator_url:
        return

    hostname = payload.hostname or _get_hostname()

    # Build findings summary
    counts: dict[str, int] = {s.value: 0 for s in Severity}
    for finding in payload.findings:
        counts[finding.severity] += 1

    import datetime

    registration = {
        "hostname": hostname,
        "ip": _get_local_ip(),
        "providers": payload.providers_run,
        "findings_summary": counts,
        "last_run": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "version": "0.1.0",
    }

    try:
        resp = httpx.post(
            f"{config.hub.coordinator_url.rstrip('/')}/api/register",
            json=registration,
            timeout=10.0,
        )
        resp.raise_for_status()
        log.info("registered with coordinator", coordinator=config.hub.coordinator_url)
    except Exception as e:
        log.warning("coordinator registration failed (non-fatal)", error=str(e))


def _get_local_ip() -> str:
    try:
        import socket

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "unknown"
