FROM mcr.microsoft.com/devcontainers/base:noble AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

# Delete the cache mounts if not building on a ubuntu based host system
RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && apt-get -y install --no-install-recommends \
        software-properties-common \
        python3 python3-pip python3-venv \
        afl++=4.09c-1ubuntu3 \
        gcc-multilib libc6-dev-i386 && \
    add-apt-repository ppa:zhangsongcui3371/fastfetch && \
    apt-get update && apt-get -y install --no-install-recommends \
        fastfetch && \
    apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

USER vscode:vscode
