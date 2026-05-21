# KYA OTLP Bridge — Dockerfile
#
# Builds a small standalone service that ingests OTLP/HTTP and posts to
# KYA's /events/rogue + /events/invocation endpoints.
#
# Built from app/agents/kya_otlp_bridge/ to keep the image lean.

FROM python:3.11-slim

WORKDIR /app

# Install deps — no agent SDKs.
# opentelemetry-proto: parse OTLP/HTTP protobuf payloads from OTel Collector
# (collector defaults to protobuf for performance; bridge handles both).
RUN pip install --no-cache-dir \
    fastapi==0.115.0 \
    uvicorn==0.30.6 \
    requests==2.32.3 \
    opentelemetry-proto==1.27.0

# Copy the bridge code AND the kya_hooks client it depends on
# (build context is app/agents/kya_otlp_bridge so we need to pull from parent)
COPY ./bridge.py     /app/kya_otlp_bridge/bridge.py
COPY ./mapper.py     /app/kya_otlp_bridge/mapper.py
COPY ./__init__.py   /app/kya_otlp_bridge/__init__.py

# kya_hooks is a sibling under app/agents/ — but since we can't COPY
# from outside the build context, we vendor the minimal client here
# at build time. Simpler than orchestrating a multi-stage build.
COPY ./kya_hooks_client.py /app/kya_hooks/__init__.py
COPY ./kya_hooks_client.py /app/kya_hooks/client.py

ENV PYTHONPATH=/app
EXPOSE 4318

CMD ["python", "-m", "kya_otlp_bridge.bridge"]
