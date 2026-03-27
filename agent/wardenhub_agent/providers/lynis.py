from __future__ import annotations

import re
import shutil
import subprocess
import time
from pathlib import Path

import structlog

from wardenhub_agent.models import Finding, Severity
from wardenhub_agent.providers.base import BaseProvider

log = structlog.get_logger()

REPORT_PATH = Path("/var/log/lynis-report.dat")
REPORT_MAX_AGE_SECONDS = 600  # 10 minutes

ARRAY_KEY_RE = re.compile(r"^(\w+)\[\]=(.+)$")
SCALAR_KEY_RE = re.compile(r"^(\w+)=(.*)$")


class ProviderError(Exception):
    pass


class LynisProvider(BaseProvider):
    id = "lynis"
    name = "Lynis"

    def __init__(self) -> None:
        self._hardening_index: int | None = None
        self._tests_performed: int | None = None

    @property
    def hardening_index(self) -> int | None:
        return self._hardening_index

    @property
    def tests_performed(self) -> int | None:
        return self._tests_performed

    @classmethod
    def detect(cls) -> bool:
        return shutil.which("lynis") is not None

    def audit(self) -> list[Finding]:
        self._run_lynis()
        return self._parse_report()

    def _run_lynis(self) -> None:
        log.info("running lynis audit")
        result = subprocess.run(
            ["lynis", "audit", "system", "--cronjob", "--quiet"],
            capture_output=True,
            text=True,
            timeout=600,
        )
        # Lynis exits 0 = clean, 1 = warnings/suggestions found (normal), 2+ = error
        if result.returncode >= 2:
            raise ProviderError(
                f"Lynis exited with code {result.returncode}: {result.stderr.strip()}"
            )
        log.debug("lynis completed", returncode=result.returncode)

    def _parse_report(self) -> list[Finding]:
        if not REPORT_PATH.exists():
            raise ProviderError(f"Lynis report not found at {REPORT_PATH}")

        age = time.time() - REPORT_PATH.stat().st_mtime
        if age > REPORT_MAX_AGE_SECONDS:
            raise ProviderError(
                f"Lynis report is {age:.0f}s old (max {REPORT_MAX_AGE_SECONDS}s). "
                "Lynis may have failed silently."
            )

        scalars: dict[str, str] = {}
        arrays: dict[str, list[str]] = {}

        for line in REPORT_PATH.read_text().splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            m = ARRAY_KEY_RE.match(line)
            if m:
                arrays.setdefault(m.group(1), []).append(m.group(2))
                continue
            m = SCALAR_KEY_RE.match(line)
            if m:
                scalars[m.group(1)] = m.group(2)

        if "hardening_index" in scalars:
            try:
                self._hardening_index = int(scalars["hardening_index"])
            except ValueError:
                log.warning("invalid hardening_index value", value=scalars["hardening_index"])

        if "tests_performed" in scalars:
            try:
                self._tests_performed = int(scalars["tests_performed"])
            except ValueError:
                pass

        findings: list[Finding] = []

        for entry in arrays.get("warning", []):
            parts = entry.split("|")
            check_id = parts[0] if parts else "UNKNOWN"
            description = parts[1] if len(parts) > 1 else entry
            findings.append(
                Finding(
                    provider=self.id,
                    check_id=check_id,
                    target="host",
                    severity=Severity.warning,
                    passed=False,
                    message=description,
                    remediation="",
                )
            )

        for entry in arrays.get("suggestion", []):
            parts = entry.split("|")
            check_id = parts[0] if parts else "UNKNOWN"
            description = parts[1] if len(parts) > 1 else entry
            findings.append(
                Finding(
                    provider=self.id,
                    check_id=check_id,
                    target="host",
                    severity=Severity.info,
                    passed=False,
                    message=description,
                    remediation="",
                )
            )

        log.info(
            "lynis report parsed",
            warnings=len(arrays.get("warning", [])),
            suggestions=len(arrays.get("suggestion", [])),
            hardening_index=self._hardening_index,
        )
        return findings
