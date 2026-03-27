from __future__ import annotations

import time

import httpx
import structlog

log = structlog.get_logger()


async def cleanup_stale_metrics(pushgateway_url: str, threshold_seconds: int) -> None:
    """Delete stale metric groups from Pushgateway for agents that haven't reported."""
    url = pushgateway_url.rstrip("/")
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.get(f"{url}/api/v1/metrics")
            resp.raise_for_status()
            data = resp.json()
    except Exception as e:
        log.warning("failed to fetch Pushgateway metrics for cleanup", error=str(e))
        return

    metric_groups = data.get("data", [])
    now = time.time()
    deleted = 0

    for group in metric_groups:
        labels = group.get("labels", {})
        job = labels.get("job", "")
        instance = labels.get("instance", "")

        if job != "wardenhub_agent":
            continue

        last_push_str = group.get("last_push", "")
        if not last_push_str:
            continue

        try:
            from datetime import datetime, timezone
            last_push_dt = datetime.fromisoformat(last_push_str.replace("Z", "+00:00"))
            last_push_ts = last_push_dt.timestamp()
        except (ValueError, AttributeError) as e:
            log.warning("failed to parse last_push timestamp", value=last_push_str, error=str(e))
            continue

        age = now - last_push_ts
        if age > threshold_seconds:
            log.info(
                "deleting stale metrics",
                instance=instance,
                age_seconds=int(age),
                threshold=threshold_seconds,
            )
            try:
                async with httpx.AsyncClient(timeout=10.0) as client:
                    delete_resp = await client.delete(
                        f"{url}/metrics/job/wardenhub_agent/instance/{instance}"
                    )
                    delete_resp.raise_for_status()
                    deleted += 1
            except Exception as e:
                log.warning("failed to delete stale metrics", instance=instance, error=str(e))

    if deleted:
        log.info("cleanup complete", deleted=deleted)
    else:
        log.debug("cleanup: no stale metrics found")
