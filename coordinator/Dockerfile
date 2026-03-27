# Stage 1: build
FROM python:3.12-slim AS builder

WORKDIR /app

# Install uv
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml .
COPY wardenhub_coordinator/ wardenhub_coordinator/

# Install dependencies into a venv
RUN uv venv /app/.venv && \
    uv pip install --python /app/.venv/bin/python .

# Stage 2: runtime
FROM python:3.12-slim

WORKDIR /app

RUN adduser --disabled-password --gecos '' wardenhub && \
    mkdir -p /data /etc/wardenhub && \
    chown wardenhub:wardenhub /data /etc/wardenhub

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/wardenhub_coordinator /app/wardenhub_coordinator

ENV PATH="/app/.venv/bin:$PATH"
ENV PYTHONUNBUFFERED=1

USER wardenhub

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8080/health').raise_for_status()"

EXPOSE 8080

CMD ["python", "-m", "uvicorn", "wardenhub_coordinator.app:app", \
     "--host", "0.0.0.0", "--port", "8080"]
