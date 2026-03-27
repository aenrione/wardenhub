from __future__ import annotations

import os
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from wardenhub_coordinator import __version__

log = structlog.get_logger()

_db = None
_config = None


def get_db():
    return _db


@asynccontextmanager
async def lifespan(app: FastAPI):
    global _db, _config

    config_path = os.environ.get("WARDENHUB_CONFIG", "/etc/wardenhub/coordinator.yaml")

    from wardenhub_coordinator.config import CoordinatorConfig, load_config
    from wardenhub_coordinator.db import Database
    from wardenhub_coordinator.scheduler import setup_scheduler

    try:
        _config = load_config(config_path)
    except Exception as e:
        log.warning("config load failed, using defaults", error=str(e))
        _config = CoordinatorConfig()

    _db = Database(_config.coordinator.db_path)
    log.info("database initialized", db_path=_config.coordinator.db_path)

    scheduler = setup_scheduler(
        pushgateway_url=_config.pushgateway.url,
        cleanup_threshold_seconds=_config.pushgateway.cleanup_threshold_seconds,
    )
    scheduler.start()
    log.info("scheduler started")

    yield

    scheduler.shutdown(wait=False)
    log.info("scheduler stopped")


app = FastAPI(
    title="WardHub Coordinator",
    version=__version__,
    lifespan=lifespan,
)


# --- Pydantic models ---

class FindingsSummary(BaseModel):
    critical: int = 0
    warning: int = 0
    info: int = 0


class AgentRegistration(BaseModel):
    hostname: str
    ip: str
    providers: list[str]
    findings_summary: dict[str, int]
    last_run: datetime
    version: str


class AgentStatus(BaseModel):
    hostname: str
    ip: str
    providers: list[str]
    findings_critical: int
    findings_warning: int
    findings_info: int
    last_run: str | None
    version: str | None
    updated_at: str | None


# --- Endpoints ---

@app.get("/health")
async def health() -> dict[str, Any]:
    return {"status": "ok", "version": __version__}


@app.post("/api/register", status_code=200)
async def register_agent(registration: AgentRegistration) -> dict[str, str]:
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database not initialized")

    db.upsert_agent(
        hostname=registration.hostname,
        ip=registration.ip,
        providers=registration.providers,
        findings_summary=registration.findings_summary,
        last_run=registration.last_run.isoformat(),
        version=registration.version,
    )
    db.add_run(
        hostname=registration.hostname,
        findings_summary=registration.findings_summary,
        run_at=registration.last_run.isoformat(),
    )

    log.info(
        "agent registered",
        hostname=registration.hostname,
        providers=registration.providers,
        findings=registration.findings_summary,
    )
    return {"status": "ok"}


@app.get("/api/status")
async def get_status() -> dict[str, Any]:
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database not initialized")

    agents = db.get_all_agents()
    return {
        "agents": agents,
        "total": len(agents),
        "version": __version__,
    }


@app.get("/api/findings")
async def get_findings() -> dict[str, Any]:
    db = get_db()
    if db is None:
        raise HTTPException(status_code=503, detail="Database not initialized")

    agents = db.get_all_agents()
    totals = {"critical": 0, "warning": 0, "info": 0}
    per_host = []

    for agent in agents:
        host_summary = {
            "hostname": agent["hostname"],
            "critical": agent["findings_critical"],
            "warning": agent["findings_warning"],
            "info": agent["findings_info"],
        }
        per_host.append(host_summary)
        totals["critical"] += agent["findings_critical"]
        totals["warning"] += agent["findings_warning"]
        totals["info"] += agent["findings_info"]

    return {
        "totals": totals,
        "per_host": per_host,
    }


def main() -> None:
    import logging

    import structlog

    logging.basicConfig(format="%(message)s", level=logging.INFO)
    structlog.configure(
        processors=[
            structlog.stdlib.filter_by_level,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        context_class=dict,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )

    config_path = os.environ.get("WARDENHUB_CONFIG", "/etc/wardenhub/coordinator.yaml")

    try:
        from wardenhub_coordinator.config import load_config
        config = load_config(config_path)
        host = config.coordinator.host
        port = config.coordinator.port
    except Exception:
        host = "0.0.0.0"
        port = 8080

    uvicorn.run(
        "wardenhub_coordinator.app:app",
        host=host,
        port=port,
        log_level="info",
    )
