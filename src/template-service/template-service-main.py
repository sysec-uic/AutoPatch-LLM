import asyncio
import json
import logging
import os
import time
from datetime import datetime

import docker
from cloudevents.http import CloudEvent
from service_config import (
    CONFIG_PATH,
    DOCKER_ENABLED,
    LOG_LEVEL,
    MQTT_HOST,
    MQTT_INPUT_TOPIC,
    MQTT_OUTPUT_TOPIC,
    MQTT_PORT,
    SERVICE_DESCRIPTION,
    SERVICE_NAME,
)

from autopatchpubsub import MessageBrokerClient
from autopatchshared import get_current_timestamp

# ----------------------------------------------------------------------
# Logging setup
# ----------------------------------------------------------------------
logging.basicConfig(
    level=LOG_LEVEL, format=f"[{SERVICE_NAME}] %(asctime)s %(levelname)s: %(message)s"
)
logger = logging.getLogger(SERVICE_NAME)
logger.info("Service initialized: %s", SERVICE_DESCRIPTION)

# ----------------------------------------------------------------------
# Docker connectivity (optional)
# ----------------------------------------------------------------------
if DOCKER_ENABLED:
    try:
        docker_client = docker.from_env()
        containers = docker_client.containers.list()
        logger.info("Connected to Docker daemon. Found %d containers.", len(containers))
    except Exception as e:
        logger.warning("Docker not reachable: %s", e)
else:
    logger.info("Docker integration disabled.")


# ----------------------------------------------------------------------
# MQTT Message Handler
# ----------------------------------------------------------------------
def handle_message(event: CloudEvent):
    """Handle incoming MQTT messages."""
    try:
        logger.info("📩 Received message on input topic:")
        print(json.dumps(event.data, indent=2))

        reply = {
            "reply": f"Hello from {SERVICE_NAME}",
            "received": event.data,
            "timestamp": time.time(),
        }

        logger.info("📤 Sending MQTT reply to output topic:")
        print(json.dumps(reply, indent=2))
        broker.publish(MQTT_OUTPUT_TOPIC, json.dumps(reply))
        logger.info("✅ Reply published to %s", MQTT_OUTPUT_TOPIC)
    except Exception as e:
        logger.error(f"Error handling message: {e}", exc_info=True)


# ----------------------------------------------------------------------
# Main logic
# ----------------------------------------------------------------------
def main():
    global broker

    broker = MessageBrokerClient(MQTT_HOST, int(MQTT_PORT), logger)
    logger.info(f"✅ Connected to MQTT broker at {MQTT_HOST}:{MQTT_PORT}")
    logger.info(f"Subscribed to {MQTT_INPUT_TOPIC}, publishing to {MQTT_OUTPUT_TOPIC}")

    # Subscribe to incoming messages
    broker.subscribe(MQTT_INPUT_TOPIC, handle_message)

    # Send startup message
    startup_data = {
        "type": "startup",
        "service": SERVICE_NAME,
        "description": SERVICE_DESCRIPTION,
        "timestamp": time.time(),
    }
    broker.publish(MQTT_OUTPUT_TOPIC, json.dumps(startup_data))
    logger.info("📤 Sent startup message:")
    print(json.dumps(startup_data, indent=2))

    # Periodic heartbeats
    counter = 1
    while True:
        heartbeat = {
            "type": "heartbeat",
            "service": SERVICE_NAME,
            "count": counter,
            "timestamp": time.time(),
        }
        broker.publish(MQTT_OUTPUT_TOPIC, json.dumps(heartbeat))
        logger.info(f"💓 Sent heartbeat #{counter}")
        print(json.dumps(heartbeat, indent=2))
        counter += 1
        time.sleep(10)


# ----------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------
if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        logger.info("Shutting down %s.", SERVICE_NAME)
    except Exception as e:
        logger.error(f"Unhandled exception: {e}", exc_info=True)
