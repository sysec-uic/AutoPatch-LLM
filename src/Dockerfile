FROM alpine:3.21.2 AS base

ENV PYTHONUNBUFFERED=1

WORKDIR /app

RUN addgroup -S appuser && \
    adduser -S appuser -G appuser && \
    apk add --no-cache python3

FROM base AS build

COPY requirements.txt .

RUN apk add --no-cache \
    py3-pip

USER appuser

RUN pip install --break-system-packages --user --no-cache-dir -r requirements.txt

FROM base AS runner

RUN apk add --no-cache gcc

COPY --from=build /home/appuser/.local /home/appuser/.local

COPY main.py /app

RUN chown -R appuser:appuser /app

USER appuser

LABEL version="0.1.0"

CMD ["python", "main.py"]
