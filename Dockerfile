FROM python:3.12.2-slim-bookworm

ENV ENV=local
ENV PROJECT_ROOT=/app
WORKDIR $PROJECT_ROOT

RUN apt update && apt install -y git gcc g++ curl apt-transport-https ca-certificates gnupg-agent software-properties-common curl

# install poetry and appsec discovery cli deps
RUN pip install --upgrade pip
RUN pip install poetry
RUN pip install pytest

COPY pyproject.toml $PROJECT_ROOT
COPY *.lock $PROJECT_ROOT

ENV CMAKE_ARGS="-DGGML_METAL=off"

RUN poetry config virtualenvs.create false
RUN poetry install --no-root --with dev

COPY . $PROJECT_ROOT

RUN PATH="$PROJECT_ROOT/bin:$PATH"
RUN PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"