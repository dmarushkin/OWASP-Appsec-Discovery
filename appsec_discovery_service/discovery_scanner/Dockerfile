FROM python:3.12.2-slim-bookworm

WORKDIR /app

COPY requirements.txt requirements.txt

RUN apt update
RUN apt install -y git gcc g++
RUN pip install --upgrade pip

ENV CMAKE_ARGS="-DGGML_METAL=off"

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]