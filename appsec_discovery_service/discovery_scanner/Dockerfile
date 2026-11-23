# Build from the repository root so the core package is installed from the current sources:
#   docker build -f appsec_discovery_service/discovery_scanner/Dockerfile .
# (docker-compose.yml does this). Build-context exclusions: Dockerfile.dockerignore next to this file.
FROM python:3.12.2-slim-bookworm

# git >= 2.31 is required for GIT_CONFIG_COUNT based auth (bookworm ships 2.39).
# (no compiler toolchain: the local LLM runs in the discovery_llm container, nothing is built here)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.8.13 /uv /bin/uv

# Core dependency versions come from uv.lock (exported as pip constraints), so the image
# resolves the same versions as CI instead of the newest ones allowed by pyproject ranges.
COPY pyproject.toml uv.lock README.md LICENSE /src/core/
RUN uv export --project /src/core --frozen --no-dev --no-emit-project --no-hashes \
        -o /src/core/constraints.txt

COPY appsec_discovery_service/discovery_scanner/requirements.txt /app/requirements.txt
RUN pip install -c /src/core/constraints.txt -r /app/requirements.txt

# Core package from the repo sources (single version source: pyproject.toml).
# requirements-core.txt pins the supported major version: pip fails if the sources differ.
COPY appsec_discovery /src/core/appsec_discovery
COPY appsec_discovery_service/discovery_scanner/requirements-core.txt /app/requirements-core.txt
RUN pip install -c /src/core/constraints.txt /src/core -r /app/requirements-core.txt

# Shared models / DB layer / migrations (P2-5).
COPY appsec_discovery_service/discovery_common/ /app/discovery_common/
COPY appsec_discovery_service/discovery_scanner/ /app/

CMD ["python", "main.py"]
