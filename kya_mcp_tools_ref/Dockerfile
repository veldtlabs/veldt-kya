# Reference MCP tools backend for the KYA gateway.
#
# Not a product — a reference implementation that shows how any tool
# becomes governed by pointing the KYA gateway at it. Fork to expose
# your own tools; the wire-up is the same.
#
# Trust boundary: this image is meant to run BEHIND the KYA gateway on
# an internal container network. The docker-compose entry for this
# service intentionally publishes NO host port. Do not `docker run -p
# 18090:18090` in production.

FROM python:3.12-slim

# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install package + runtime deps. Version pins live in pyproject.toml
# under the `mcp-tools-ref` extra.
COPY pyproject.toml /app/pyproject.toml
COPY kya_mcp_tools_ref /app/kya_mcp_tools_ref
# `-e .[mcp-tools-ref]` pulls the mcp-tools-ref extra (aiohttp + httpx)
# declared in pyproject.toml. Installing without the extra reproduces
# the "aiohttp works, httpx ImportError at first tool call" class of
# bug that OSS-clean-venv-test-before-push memory is about.
RUN pip install --no-cache-dir -e ".[mcp-tools-ref]"

# Non-root runtime user. The scratch dir is a docker volume; ownership
# set here is authoritative when the volume is first initialised from
# an empty state. If a pre-existing volume masks this ownership, run
# a one-time `docker exec --user root kya-mcp-tools-ref chown -R
# kya:kya /var/lib/kya-mcp-tools-ref/scratch` after upgrade.
RUN groupadd -r kya --gid=1000 \
    && useradd -r -u 1000 -g kya --home-dir=/app --shell=/bin/false kya \
    && install -d -o kya -g kya /var/lib/kya-mcp-tools-ref/scratch
USER kya

# Fail-closed defaults:
#   - governed_bash NOT registered (KYA_MCP_ENABLE_BASH unset)
#   - test endpoints NOT exposed (KYA_MCP_TEST_MODE unset)
# The compose file overrides these for local dev where appropriate.

EXPOSE 18090

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD curl -sf http://localhost:18090/healthz || exit 1

# Single-worker by design (aiohttp default). Do not wrap with gunicorn.
CMD ["python", "-m", "kya_mcp_tools_ref", "--host", "0.0.0.0", "--port", "18090"]
