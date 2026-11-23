FROM python:3.12.2-slim-bookworm

ENV PROJECT_ROOT=/app
WORKDIR $PROJECT_ROOT

# git: semgrep and the tests; no compiler toolchain (every dependency ships wheels)
RUN apt-get update \
    && apt-get install -y --no-install-recommends git curl ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# install uv and appsec discovery cli deps (incl. dev group) into system python
COPY --from=ghcr.io/astral-sh/uv:0.8.13 /uv /uvx /bin/
ENV UV_PROJECT_ENVIRONMENT=/usr/local \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1

COPY pyproject.toml uv.lock $PROJECT_ROOT/

RUN uv sync --locked --no-install-project

COPY . $PROJECT_ROOT
