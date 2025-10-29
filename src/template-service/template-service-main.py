import json
import logging
import os
import time

import docker
from service_config import CONFIG_PATH, LOG_LEVEL, SERVICE_DESCRIPTION, SERVICE_NAME

logging.basicConfig(
    level=LOG_LEVEL, format=f"[{SERVICE_NAME}] %(asctime)s %(levelname)s: %(message)s"
)
log = logging.getLogger(SERVICE_NAME)

log.info("Service initialized: %s", SERVICE_DESCRIPTION)
if os.path.exists(CONFIG_PATH):
    try:
        with open(CONFIG_PATH) as f:
            cfg = json.load(f)
        log.info("Loaded config: %s", cfg)
    except Exception as e:
        log.warning("Config load failed: %s", e)
else:
    log.warning("Config file not found at %s", CONFIG_PATH)

# Docker connectivity test
try:
    client = docker.from_env()
    containers = client.containers.list()
    log.info("Connected to Docker daemon. Found %d containers.", len(containers))
except Exception as e:
    log.error("Docker access failed: %s", e)

# Keep alive
try:
    while True:
        log.info("Heartbeat — %s running.", SERVICE_NAME)
        time.sleep(15)
except KeyboardInterrupt:
    log.info("Shutting down %s.", SERVICE_NAME)
