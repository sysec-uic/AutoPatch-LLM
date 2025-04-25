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

COPY autopatchdatatypes-0.8.0-py3-none-any.whl .
COPY autopatchshared-0.8.0-py3-none-any.whl .
COPY autopatchpubsub-0.8.0-py3-none-any.whl .

RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

# Stage 3: Final runtime image
FROM base AS final

RUN apt-get install -y --no-install-recommends \
        gcc=4:13.2.0-7ubuntu1 \
        gcc-multilib=4:13.2.0-7ubuntu1 \
        libc6-dev-i386=2.39-0ubuntu8.4 && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy installed Python packages
COPY --from=python-builder /usr/lib/python3/dist-packages /usr/lib/python3/dist-packages
COPY --from=python-builder /usr/local/lib/python3.12/dist-packages /usr/local/lib/python3.12/dist-packages

COPY patch_evaluation_service.py /app/patch_evaluation_service.py
COPY patch_eval_config.py /app/patch_eval_config.py


CMD ["python3", "patch_evaluation_service.py"]
