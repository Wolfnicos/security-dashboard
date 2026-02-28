# ── Stage 1: Builder ────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /build

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# ── Stage 2: Runtime ────────────────────────────────────
FROM python:3.11-slim

RUN groupadd --gid 1000 appuser \
    && useradd --uid 1000 --gid appuser --create-home appuser

WORKDIR /app

COPY --from=builder /install /usr/local
COPY app/ app/
COPY config/ config/
COPY scripts/ scripts/
COPY run.py .

RUN mkdir -p /app/data && chown -R appuser:appuser /app

USER appuser

EXPOSE 5000

CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "2", "--timeout", "120", "run:app"]
