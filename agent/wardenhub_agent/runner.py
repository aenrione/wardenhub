from __future__ import annotations

import time
from dataclasses import dataclass, field

import structlog

from wardenhub_agent.config import Config, ConfigError
from wardenhub_agent.models import Finding
from wardenhub_agent.providers import ALL_PROVIDERS
from wardenhub_agent.providers.base import BaseProvider
from wardenhub_agent.providers.lynis import LynisProvider
from wardenhub_agent.providers.network import NetworkProvider
from wardenhub_agent.pusher import PushPayload, push_metrics, register_with_coordinator

log = structlog.get_logger()


@dataclass
class RunResult:
    findings: list[Finding] = field(default_factory=list)
    provider_errors: dict[str, bool] = field(default_factory=dict)
    provider_metrics: dict[str, dict[str, float]] = field(default_factory=dict)
    providers_run: list[str] = field(default_factory=list)


def _select_providers(config: Config) -> list[BaseProvider]:
    """Select and instantiate providers based on config and auto-detection."""
    if config.providers.enabled is not None and config.providers.disabled:
        raise ConfigError(
            "providers.enabled and providers.disabled cannot both be set."
        )

    selected: list[BaseProvider] = []

    for provider_cls in ALL_PROVIDERS:
        if config.providers.enabled is not None:
            if provider_cls.id not in config.providers.enabled:
                log.debug("provider not in enabled list, skipping", provider=provider_cls.id)
                continue
            # Skip detect() when explicit list is given
            selected.append(_instantiate_provider(provider_cls, config))
            continue

        if provider_cls.id in config.providers.disabled:
            log.debug("provider disabled, skipping", provider=provider_cls.id)
            continue

        try:
            if provider_cls.detect():
                log.info("provider detected", provider=provider_cls.id)
                selected.append(_instantiate_provider(provider_cls, config))
            else:
                log.debug("provider not detected", provider=provider_cls.id)
        except Exception as e:
            log.warning("provider detect() raised exception, skipping", provider=provider_cls.id, error=str(e))

    return selected


def _instantiate_provider(provider_cls: type[BaseProvider], config: Config) -> BaseProvider:
    """Instantiate a provider, passing config if needed."""
    if provider_cls is NetworkProvider:
        return NetworkProvider(config=config)
    return provider_cls()


def run_once(config: Config) -> RunResult:
    """Run a single audit cycle."""
    result = RunResult()

    providers = _select_providers(config)
    if not providers:
        log.warning("no providers selected, nothing to audit")
        return result

    for provider in providers:
        result.providers_run.append(provider.id)
        log.info("running provider", provider=provider.id)
        try:
            findings = provider.audit()
            result.findings.extend(findings)
            log.info(
                "provider completed",
                provider=provider.id,
                findings=len(findings),
            )
        except Exception as e:
            log.error("provider audit() failed", provider=provider.id, error=str(e))
            result.provider_errors[provider.id] = True

        # Extract provider-specific metrics
        if isinstance(provider, LynisProvider):
            metrics: dict[str, float] = {}
            if provider.hardening_index is not None:
                metrics["hardening_index"] = float(provider.hardening_index)
            if provider.tests_performed is not None:
                metrics["tests_performed"] = float(provider.tests_performed)
            if metrics:
                result.provider_metrics["lynis"] = metrics

    payload = PushPayload(
        findings=result.findings,
        provider_errors=result.provider_errors,
        provider_metrics=result.provider_metrics,
        providers_run=result.providers_run,
    )

    push_metrics(payload, config)
    register_with_coordinator(payload, config)

    return result


def run_loop(config: Config) -> None:
    """Run audit on a recurring schedule (daemon mode)."""
    interval = config.schedule.interval_seconds
    log.info("starting audit loop", interval_seconds=interval)
    while True:
        try:
            result = run_once(config)
            log.info(
                "audit cycle complete",
                findings=len(result.findings),
                errors=list(result.provider_errors.keys()),
            )
        except Exception as e:
            log.error("audit cycle failed", error=str(e))
        log.info("sleeping until next audit", seconds=interval)
        time.sleep(interval)
