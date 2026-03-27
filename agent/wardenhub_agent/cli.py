from __future__ import annotations

import sys
from pathlib import Path

import structlog
import typer

app = typer.Typer(name="wardenhub-agent", help="WardHub security auditing agent")

DEFAULT_CONFIG = "/etc/wardenhub/agent.yaml"


def _setup_logging(level: str) -> None:
    import logging
    import structlog

    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper(), logging.INFO),
    )
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.stdlib.add_logger_name,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )


@app.command()
def run(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c", help="Path to config file"),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level"),
) -> None:
    """Run a single audit and exit."""
    _setup_logging(log_level)
    log = structlog.get_logger()

    from wardenhub_agent.config import ConfigError, load_config
    from wardenhub_agent.pusher import PushError
    from wardenhub_agent.runner import run_once

    try:
        cfg = load_config(config)
    except ConfigError as e:
        log.error("config error", error=str(e))
        raise typer.Exit(code=1)

    try:
        result = run_once(cfg)
        log.info(
            "audit complete",
            findings=len(result.findings),
            providers=result.providers_run,
        )
    except PushError as e:
        log.error("push failed", error=str(e))
        raise typer.Exit(code=1)
    except Exception as e:
        log.error("unexpected error", error=str(e))
        raise typer.Exit(code=1)


@app.command()
def start(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c", help="Path to config file"),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level"),
) -> None:
    """Run in daemon mode with built-in scheduler."""
    _setup_logging(log_level)
    log = structlog.get_logger()

    from wardenhub_agent.config import ConfigError, load_config
    from wardenhub_agent.runner import run_loop

    try:
        cfg = load_config(config)
    except ConfigError as e:
        log.error("config error", error=str(e))
        raise typer.Exit(code=1)

    run_loop(cfg)


@app.command()
def init(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c", help="Path to write config"),
    log_level: str = typer.Option("INFO", "--log-level", help="Log level"),
) -> None:
    """Generate a config file with auto-detected providers."""
    _setup_logging(log_level)
    log = structlog.get_logger()

    from wardenhub_agent.providers import ALL_PROVIDERS

    detected = []
    for provider_cls in ALL_PROVIDERS:
        try:
            if provider_cls.detect():
                detected.append(provider_cls.id)
                log.info("detected provider", provider=provider_cls.id)
        except Exception as e:
            log.warning("detect() failed", provider=provider_cls.id, error=str(e))

    pushgateway_url = typer.prompt("Pushgateway URL", default="http://localhost:9091")
    coordinator_url = typer.prompt(
        "Coordinator URL (leave empty to skip)", default="", prompt_suffix=": "
    )

    config.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        "hub:",
        f'  pushgateway_url: "{pushgateway_url}"',
    ]
    if coordinator_url:
        lines.append(f'  coordinator_url: "{coordinator_url}"')

    lines += [
        "",
        "schedule:",
        '  interval: "3h"',
        "",
        "providers:",
        "  # Detected providers: " + ", ".join(detected),
        "  # Uncomment to override auto-detection:",
        "  # enabled: [" + ", ".join(detected) + "]",
        "",
        "network:",
        "  expected_ports: [22]",
    ]

    config.write_text("\n".join(lines) + "\n")
    log.info("config written", path=str(config))
    typer.echo(f"Config written to {config}")


@app.command()
def status(
    config: Path = typer.Option(DEFAULT_CONFIG, "--config", "-c", help="Path to config file"),
) -> None:
    """Query coordinator status."""
    import httpx

    from wardenhub_agent.config import ConfigError, load_config

    try:
        cfg = load_config(config)
    except ConfigError as e:
        typer.echo(f"Config error: {e}", err=True)
        raise typer.Exit(code=1)

    if not cfg.hub.coordinator_url:
        typer.echo("coordinator_url not configured", err=True)
        raise typer.Exit(code=1)

    try:
        resp = httpx.get(f"{cfg.hub.coordinator_url.rstrip('/')}/api/status", timeout=10.0)
        resp.raise_for_status()
        import json

        typer.echo(json.dumps(resp.json(), indent=2))
    except Exception as e:
        typer.echo(f"Error querying coordinator: {e}", err=True)
        raise typer.Exit(code=1)
