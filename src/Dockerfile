FROM ubuntu:noble AS base

# Set environment variables to prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && apt-get install -y --no-install-recommends python3

# Set Python as default
RUN update-alternatives --install /usr/bin/python python /usr/bin/python3 1

FROM base AS build

COPY requirements.txt .

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    apt-get install -y --no-install-recommends \
    python3-pip && \
    pip install --break-system-packages --user --no-cache-dir -r requirements.txt

FROM base AS runner

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    apt-get install -y --no-install-recommends \
    gcc && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create a non-root user and group
RUN groupadd -r appuser && useradd -r -g appuser -d /app -s /bin/bash appuser

# Copy files and change ownership
COPY main.py /app

COPY --from=build /root/.local /app/.local
RUN chown -R appuser:appuser /app

# Update PATH for installed Python packages
ENV PATH=/app/.local/bin:$PATH

USER appuser

CMD ["python", "main.py"]
