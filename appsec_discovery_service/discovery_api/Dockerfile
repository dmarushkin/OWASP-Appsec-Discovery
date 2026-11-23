# Build context: appsec_discovery_service/ (the shared discovery_common package is copied in):
#   docker build -f discovery_api/Dockerfile .
# This image also runs the one-shot schema migration (`python -m discovery_common.migrate`).
FROM python:3.12.2-slim-bookworm

WORKDIR /app

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY discovery_api/requirements.txt .
RUN pip install -r requirements.txt

COPY discovery_common/ /app/discovery_common/
COPY discovery_api/ /app/

# --root-path: served behind nginx at /api (P3-2: /api/docs works)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--root-path", "/api", "--proxy-headers"]
