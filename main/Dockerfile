FROM ubuntu:noble AS base

# Set environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends python3

# Set Python as default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

FROM base AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip

COPY requirements.txt .
RUN pip install --break-system-packages --user --no-cache-dir -r requirements.txt

FROM python:3.12-slim as runner

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Set ownership of the working directory
WORKDIR /app

# Copy files and change ownership
COPY main.py /app

COPY --from=build /root/.local /app/.local
RUN chown -R appuser:appuser /app

# Update PATH for installed Python packages
ENV PATH=/app/.local/bin:$PATH

USER appuser

CMD ["python", "main.py"]
