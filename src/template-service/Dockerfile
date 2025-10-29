# Stage 0: Base
FROM ubuntu:noble AS base
LABEL org.opencontainers.image.description="AutoPatch Empty Service (Docker-aware)"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        docker.io \
        ca-certificates \
        curl \
        iputils-ping \
        git && \
    rm -rf /var/lib/apt/lists/*
# Stage 1: Python deps
FROM base AS python-builder

ENV PYTHONUNBUFFERED=1
WORKDIR /deps

COPY requirements.txt .
RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

# Stage 2: Final runtime image
FROM base AS final
ENV PYTHONUNBUFFERED=1

WORKDIR /app

# Copy Python deps from builder
COPY --from=python-builder /usr/lib/python3/dist-packages /usr/lib/python3/dist-packages
COPY --from=python-builder /usr/local/lib/python3.12/dist-packages /usr/local/lib/python3.12/dist-packages

# Copy service code
COPY service_config.py .
COPY template-service-main.py .
COPY .env .

# Make Docker CLI available in PATH
ENV PATH="/usr/bin:$PATH"

CMD ["python3", "template-service-main.py"]
