FROM ubuntu:noble AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1

WORKDIR /app

# Install required packages and clean up apt cache
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3=3.12.3-0ubuntu2 \
        python3-pip=24.0+dfsg-1ubuntu1.1 \
        openjdk-21-jdk-headless \
        curl=8.5.0-2ubuntu10.6 \
        gzip=1.12-1ubuntu3 \ 
        unzip=6.0-28ubuntu4.1 

RUN curl -fLo coursier https://github.com/coursier/launchers/raw/master/coursier && \
    chmod +x coursier && \
    ./coursier \
    ./coursier install scala:3.3.5

RUN curl -L "https://github.com/joernio/joern/releases/download/v4.0.247/joern-install.sh" -o joern-install.sh && \
    chmod u+x joern-install.sh && \
    ./joern-install.sh

RUN rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

COPY autopatchshared-0.4.1-py3-none-any.whl .
COPY autopatchdatatypes-0.4.1-py3-none-any.whl .
COPY autopatchpubsub-0.4.1-py3-none-any.whl .

RUN pip install --break-system-packages --no-cache-dir -r requirements.txt

RUN rm /app/autopatchshared-0.4.1-py3-none-any.whl \
    /app/autopatchpubsub-0.4.1-py3-none-any.whl \
    /app/autopatchdatatypes-0.4.1-py3-none-any.whl \
    /app/joern-cli.zip \
    /app/requirements.txt \
    /app/coursier

COPY cpg_svc_config.py /app/cpg_svc_config.py
COPY code_property_graph_generator.py /app/code_property_graph_generator.py

CMD ["python3", "code_property_graph_generator.py"]
