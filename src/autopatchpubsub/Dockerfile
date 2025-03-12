# This file is a developement tool and example code only and can be used to test the MQTT broker.
FROM ubuntu:noble AS base

ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Install required packages and clean up apt cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3=3.12.3-0ubuntu2 \
        python3-pip=24.0+dfsg-1ubuntu1.1 && \
    rm -rf /var/lib/apt/lists/*

# Create a system group and user named "appuser"
RUN groupadd -r appuser && \
    useradd -r -g appuser appuser

COPY requirements.txt /app/requirements.txt
RUN pip install --break-system-packages --user --no-cache-dir -r /app/requirements.txt
COPY mqtt-produce-consume.py /app/mqtt-produce-consume.py

RUN chown -R appuser:appuser /app

CMD ["python3", "/app/mqtt-produce-consume.py"]
