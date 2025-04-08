FROM ubuntu:noble AS base

LABEL org.opencontainers.image.description="Fuzzing Service"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# Install required packages and clean up apt cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3=3.12.3-0ubuntu2

# Stage 2: Install Python and pip deps
FROM base AS python-builder

RUN apt-get install -y --no-install-recommends \
        python3-pip=24.0+dfsg-1ubuntu1.1

WORKDIR /deps

COPY requirements.txt .
COPY autopatchshared-0.6.2-py3-none-any.whl .
COPY autopatchdatatypes-0.6.2-py3-none-any.whl .
COPY autopatchpubsub-0.6.2-py3-none-any.whl .

RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

# Stage 3: Final runtime image
FROM base AS final

# Install required packages and clean up apt cache
RUN apt-get install -y --no-install-recommends \
        gcc=4:13.2.0-7ubuntu1 \
        gcc-multilib=4:13.2.0-7ubuntu1 \
        afl++=4.09c-1ubuntu3 \
        libc6-dev-i386=2.39-0ubuntu8.4 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed Python packages
COPY --from=python-builder /usr/lib/python3/dist-packages /usr/lib/python3/dist-packages
COPY --from=python-builder /usr/local/lib/python3.12/dist-packages /usr/local/lib/python3.12/dist-packages

# Copy application code
COPY fuzz_svc_config.py /app/fuzz_svc_config.py
COPY fuzzing_service.py /app/fuzzing_service.py

CMD ["python3", "fuzzing_service.py"]
