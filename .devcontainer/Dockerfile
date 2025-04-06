FROM mcr.microsoft.com/devcontainers/base:noble AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && apt-get -y install --no-install-recommends \
        software-properties-common=0.99.49.1 \
        python3=3.12.3-0ubuntu2 \
        python3-pip=24.0+dfsg-1ubuntu1.1 \
        python3-venv=3.12.3-0ubuntu2 \
        afl++=4.09c-1ubuntu3 \
        gnupg=2.4.4-2ubuntu17.2 \
        gcc-multilib=4:13.2.0-7ubuntu1 \
        libc6-dev-i386=2.39-0ubuntu8.4 && \
    add-apt-repository ppa:zhangsongcui3371/fastfetch && \
    apt-get update && apt-get -y install --no-install-recommends \
        fastfetch=2.39.1 && \
    apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/* && \
    wget https://github.com/joernio/joern/releases/download/v4.0.247/joern-install.sh && \
    chmod +x ./joern-install.sh && \
    sudo ./joern-install.sh

USER vscode:vscode
