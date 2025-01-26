FROM python:3.12.2-slim-bookworm

WORKDIR /app

COPY requirements.txt requirements.txt

RUN apt update
RUN apt install -y git

RUN pip install --upgrade pip
RUN pip install poetry
RUN pip install pytest

COPY ../pyproject.toml $PROJECT_ROOT
COPY ../poetry.lock $PROJECT_ROOT
COPY ../appsec_discovery $PROJECT_ROOT

ENV CMAKE_ARGS="-DGGML_METAL=off"

RUN poetry config virtualenvs.create false
RUN poetry install --no-root --with dev

COPY . $PROJECT_ROOT


RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]