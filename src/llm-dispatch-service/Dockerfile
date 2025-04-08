FROM ubuntu:noble AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3=3.12.3-0ubuntu2

FROM base AS python-builder

RUN apt-get install -y --no-install-recommends \
        python3-pip=24.0+dfsg-1ubuntu1.1

WORKDIR /deps

COPY requirements.txt .
COPY autopatchshared-0.6.1-py3-none-any.whl .
COPY autopatchdatatypes-0.6.1-py3-none-any.whl .
COPY autopatchpubsub-0.6.1-py3-none-any.whl .

RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

# Stage 3: Final runtime image
FROM base AS final

RUN rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed Python packages
COPY --from=python-builder /usr/lib/python3/dist-packages /usr/lib/python3/dist-packages
COPY --from=python-builder /usr/local/lib/python3.12/dist-packages /usr/local/lib/python3.12/dist-packages

# Copy application code
COPY llm_dispatch_svc_config.py .
COPY llm_dispatch_svc.py .

CMD ["python3", "llm_dispatch_svc.py"]
