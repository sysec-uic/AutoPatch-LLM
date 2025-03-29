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
        afl++=4.09c-1ubuntu3 \
        libc6-dev-i386=2.39-0ubuntu8.4 && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

COPY autopatchshared-0.4.1-py3-none-any.whl .
COPY autopatchdatatypes-0.4.1-py3-none-any.whl .
COPY autopatchpubsub-0.4.1-py3-none-any.whl .

RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

COPY fuzz_svc_config.py /app/fuzz_svc_config.py
COPY fuzzing_service.py /app/fuzzing_service.py

CMD ["python3", "fuzzing_service.py"]
