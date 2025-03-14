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

RUN apk add --no-cache gcc=14.2.0-r4

COPY --from=build /home/appuser/.local /home/appuser/.local

COPY main.py /app

RUN chown -R appuser:appuser /app

USER appuser

CMD ["python", "main.py"]
