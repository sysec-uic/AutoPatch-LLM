FROM mcr.microsoft.com/devcontainers/base:noble AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

RUN --mount=target=/var/lib/apt/lists,type=cache,sharing=locked \
    --mount=target=/var/cache/apt,type=cache,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && \
    apt-get update && apt-get -y install --no-install-recommends \
        software-properties-common \
        python3 python3-pip python3-venv && \
    add-apt-repository ppa:zhangsongcui3371/fastfetch && \
    apt-get update && apt-get -y install --no-install-recommends \
        gcc-multilib libc6-dev-i386 \
        fastfetch && \
    apt-get autoremove -y && apt-get clean -y && rm -rf /var/lib/apt/lists/*

# # Install AFL++
# RUN git clone https://github.com/AFLplusplus/AFLplusplus.git /opt/AFLplusplus \
#     && cd /opt/AFLplusplus \
#     && make distrib \
#     && make install

USER vscode:vscode
