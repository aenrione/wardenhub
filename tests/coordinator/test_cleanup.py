from __future__ import annotations

import time
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from wardenhub_coordinator.cleanup import cleanup_stale_metrics


def make_pushgateway_response(instance: str, age_seconds: int) -> dict:
    from datetime import datetime, timezone, timedelta
    last_push = (datetime.now(timezone.utc) - timedelta(seconds=age_seconds)).isoformat()
    return {
        "status": "success",
        "data": [
            {
                "labels": {"job": "wardenhub_agent", "instance": instance},
                "last_push": last_push,
            }
        ],
    }


@pytest.mark.asyncio
async def test_stale_agent_gets_deleted(mocker):
    threshold = 3600  # 1 hour
    response_data = make_pushgateway_response("old-host", age_seconds=7200)  # 2 hours old

    mock_get = AsyncMock()
    mock_get.return_value.raise_for_status = MagicMock()
    mock_get.return_value.json = MagicMock(return_value=response_data)

    mock_delete = AsyncMock()
    mock_delete.return_value.raise_for_status = MagicMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get
    mock_client.delete = mock_delete

    mocker.patch("wardenhub_coordinator.cleanup.httpx.AsyncClient", return_value=mock_client)

    await cleanup_stale_metrics("http://pushgateway:9091", threshold)

    mock_delete.assert_called_once()
    delete_url = mock_delete.call_args[0][0]
    assert "old-host" in delete_url


@pytest.mark.asyncio
async def test_fresh_agent_not_deleted(mocker):
    threshold = 3600
    response_data = make_pushgateway_response("fresh-host", age_seconds=60)  # 1 minute old

    mock_get = AsyncMock()
    mock_get.return_value.raise_for_status = MagicMock()
    mock_get.return_value.json = MagicMock(return_value=response_data)

    mock_delete = AsyncMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get
    mock_client.delete = mock_delete

    mocker.patch("wardenhub_coordinator.cleanup.httpx.AsyncClient", return_value=mock_client)

    await cleanup_stale_metrics("http://pushgateway:9091", threshold)

    mock_delete.assert_not_called()


@pytest.mark.asyncio
async def test_pushgateway_unreachable_does_not_crash(mocker):
    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = AsyncMock(side_effect=Exception("connection refused"))

    mocker.patch("wardenhub_coordinator.cleanup.httpx.AsyncClient", return_value=mock_client)

    # Should not raise
    await cleanup_stale_metrics("http://pushgateway:9091", 3600)


@pytest.mark.asyncio
async def test_non_wardenhub_job_not_deleted(mocker):
    """Jobs other than wardenhub_agent should not be deleted."""
    response_data = {
        "status": "success",
        "data": [
            {
                "labels": {"job": "node_exporter", "instance": "some-host"},
                "last_push": "2020-01-01T00:00:00Z",  # very old
            }
        ],
    }

    mock_get = AsyncMock()
    mock_get.return_value.raise_for_status = MagicMock()
    mock_get.return_value.json = MagicMock(return_value=response_data)
    mock_delete = AsyncMock()

    mock_client = AsyncMock()
    mock_client.__aenter__ = AsyncMock(return_value=mock_client)
    mock_client.__aexit__ = AsyncMock(return_value=False)
    mock_client.get = mock_get
    mock_client.delete = mock_delete

    mocker.patch("wardenhub_coordinator.cleanup.httpx.AsyncClient", return_value=mock_client)

    await cleanup_stale_metrics("http://pushgateway:9091", 3600)

    mock_delete.assert_not_called()
