FROM ubuntu:noble AS base

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install required packages and clean up apt cache
RUN apt-get update && \
    apt-get install -y python3 gcc gcc-multilib libc6-dev-i386 && \
    rm -rf /var/lib/apt/lists/*

# Create a system group and user named "appuser"
RUN groupadd -r appuser && \
    useradd -r -g appuser appuser

COPY config.json /app/config/config.json
COPY logging-config.json /app/config/logging-config.json
COPY fuzzing_service.py /app/fuzzing_service.py
RUN mkdir -p /app/logs && touch /app/logs/debug.log

RUN chown -R appuser:appuser /app

LABEL version="0.1.0"

CMD ["python3", "fuzzing_service.py"]
