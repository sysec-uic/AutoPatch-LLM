FROM mcr.microsoft.com/devcontainers/base:noble AS base

ENV DEBIAN_FRONTEND=noninteractive \
    CUSTOM_VERSION=4.0.247 \
    PYTHONUNBUFFERED=1

RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && apt-get -y install --no-install-recommends \
        software-properties-common \
        python3 python3-pip python3-venv \
        afl++ \
        gcc-multilib libc6-dev-i386 && \
    add-apt-repository ppa:zhangsongcui3371/fastfetch && \
    apt-get update && apt-get -y install --no-install-recommends \
        fastfetch && \
    apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/* && \
    #export CUSTOM_VERSION=4.0.247 && \
    wget https://github.com/joernio/joern/releases/download/v4.0.247/joern-install.sh && \
    chmod +x ./joern-install.sh && \
    sudo ./joern-install.sh
    
USER vscode:vscode

