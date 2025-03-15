FROM ubuntu:noble AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install required packages and clean up apt cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3=3.12.3-0ubuntu2 \
        python3-pip=24.0+dfsg-1ubuntu1.1 \
        gcc=4:13.2.0-7ubuntu1 \
        gcc-multilib=4:13.2.0-7ubuntu1 \
        libc6-dev-i386=2.39-0ubuntu8.4 && \
    rm -rf /var/lib/apt/lists/*

# Create a system group and user named "appuser"
RUN groupadd -r appuser && \
    useradd -r -g appuser appuser

COPY requirements.txt .

COPY autopatchdatatypes-0.3.2-py3-none-any.whl .
COPY autopatchshared-0.3.2-py3-none-any.whl .

RUN pip install --break-system-packages --user --no-cache-dir -r requirements.txt

COPY patch_evaluation_service.py /app/patch_evaluation_service.py
COPY patch_eval_config.py /app/patch_eval_config.py

RUN chown -R appuser:appuser /app

CMD ["python3", "patch_evaluation_service.py"]
