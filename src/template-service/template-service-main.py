import asyncio
import json
import logging
import os
import sys
import time
from datetime import datetime
from typing import Final

from cloudevents.conversion import to_json
from cloudevents.http import CloudEvent
from autopatchpubsub import MessageBrokerClient
from autopatchshared import get_current_timestamp, init_logging

# ----------------------------------------------------------------------
# Constants / Config
# ----------------------------------------------------------------------
CONST_TEMPLATE_SVC_CONFIG: Final[str] = "TEMPLATE_SVC_CONFIG"

# ----------------------------------------------------------------------
# Globals check github
# ----------------------------------------------------------------------
logger = logging.getLogger(__name__)
message_broker_client: MessageBrokerClient = None


# ----------------------------------------------------------------------
# Create and send CloudEvent
# ----------------------------------------------------------------------
async def send_test_event():
    """Send a test CloudEvent message through MQTT."""

    attributes = {
        "type": "autopatch.template.message",
        "source": "autopatch.template-service",
        "subject": "test-message",
        "time": get_current_timestamp(),
    }

    data = {
        "message": "Hello from template-service 🚀",
        "timestamp": get_current_timestamp(),
    }

    event = CloudEvent(attributes, data)
    payload = to_json(event).decode("utf-8")

    logger.info(f"Sending CloudEvent to topic: autopatch/template-service/out")
    print(json.dumps(data, indent=2))
    await message_broker_client.publish("autopatch/template-service/out", payload)
    logger.info("Test CloudEvent published successfully.")


# ----------------------------------------------------------------------
# Main async entrypoint
# ----------------------------------------------------------------------
async def main():
    global message_broker_client, logger

    # (Optional) Load logging
    logger = init_logging(None, "autopatch.template-service")
    logger.info("Template service starting up...")

    mqtt_host = os.getenv("MQTT_HOST", "mosquitto")
    mqtt_port = int(os.getenv("MQTT_PORT", "1883"))

    # Initialize message broker client (auto-connects)
    message_broker_client = MessageBrokerClient(mqtt_host, mqtt_port, logger)
    logger.info(f"✅ Connected to MQTT broker at {mqtt_host}:{mqtt_port}")

    # Send a single test event
    await send_test_event()

    # Periodically send heartbeats
    counter = 1
    while True:
        heartbeat_data = {
            "type": "heartbeat",
            "service": "template-service",
            "count": counter,
            "timestamp": get_current_timestamp(),
        }
        event = CloudEvent(
            {"type": "autopatch.template.heartbeat", "source": "template-service"},
            heartbeat_data,
        )
        payload = to_json(event).decode("utf-8")
        await message_broker_client.publish("autopatch/template-service/out", payload)
        logger.info(f"Heartbeat #{counter} published.")
        print(json.dumps(heartbeat_data, indent=2))
        counter += 1
        await asyncio.sleep(10)


# ----------------------------------------------------------------------
# Entrypoint
# ----------------------------------------------------------------------
if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user. Exiting.")
    except Exception as e:
        logging.error(f"Unhandled exception: {e}", exc_info=True)
        sys.exit(1)
