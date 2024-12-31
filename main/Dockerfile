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

WORKDIR /app

COPY . /app
COPY --from=build /root/.local /root/.local

# # Update PATH for installed Python packages
ENV PATH=/root/.local/bin:$PATH

CMD ["python", "main.py"]
