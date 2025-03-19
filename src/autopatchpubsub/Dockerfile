# This file is a developement tool and example code only and can be used to test the MQTT broker.

FROM alpine:3.21.2 AS base

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup -S appuser && \
    adduser -S appuser -G appuser && \
    apk add --no-cache python3=3.12.9-r0

FROM base AS build

COPY requirements.txt .

RUN apk add --no-cache \
    py3-pip=24.3.1-r0

USER appuser

RUN pip install --break-system-packages --user --no-cache-dir -r requirements.txt

FROM base AS runner

COPY --from=build /home/appuser/.local /home/appuser/.local

COPY mqtt-produce-consume.py /app/mqtt-produce-consume.py

RUN chown -R appuser:appuser /app

USER appuser

CMD ["python3", "/app/mqtt-produce-consume.py"]
