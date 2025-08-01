# Stage 0: Base
FROM ubuntu:noble AS base

LABEL org.opencontainers.image.description="Code Property Graph Service"

ENV DEBIAN_FRONTEND=noninteractive

# hadolint ignore=DL3008
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        openjdk-21-jdk-headless \
        python3=3.12.3-0ubuntu2

# Stage 1: Build Joern using minimal tools
FROM base AS joern-builder

ENV DEBIAN_FRONTEND=noninteractive


# hadolint ignore=DL3008
RUN apt-get install -y --no-install-recommends \
        ca-certificates=20240203 \
        curl=8.5.0-2ubuntu10.6 \
        gzip \
        unzip=6.0-28ubuntu4.1

WORKDIR /tools

RUN curl -fLo coursier https://github.com/coursier/launchers/raw/master/coursier && \
    chmod +x coursier && \
    ./coursier install scala:3.3.5

RUN curl -L "https://github.com/joernio/joern/releases/download/v4.0.324/joern-install.sh" -o joern-install.sh && \
    chmod +x joern-install.sh && \
    ./joern-install.sh

# Stage 2: Install Python and pip deps
FROM base AS python-builder

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get install -y --no-install-recommends \
        python3-pip=24.0+dfsg-1ubuntu1.2

WORKDIR /deps

COPY requirements.txt .
COPY autopatchshared-0.9.1-py3-none-any.whl .
COPY autopatchdatatypes-0.9.1-py3-none-any.whl .
COPY autopatchpubsub-0.9.1-py3-none-any.whl .

RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

# Stage 3: Final runtime image
FROM base AS final

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/joern/joern-cli:$PATH"

WORKDIR /app

# Copy installed Python packages
COPY --from=python-builder /usr/lib/python3/dist-packages /usr/lib/python3/dist-packages
COPY --from=python-builder /usr/local/lib/python3.12/dist-packages /usr/local/lib/python3.12/dist-packages

# Copy Joern tools
COPY --from=joern-builder /opt/joern /opt/joern

# Copy application code
COPY cpg_svc_config.py .
COPY code_property_graph_generator.py .

RUN rm -rf /var/lib/apt/lists/*

CMD ["python3", "code_property_graph_generator.py"]
