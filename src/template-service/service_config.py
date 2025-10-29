import os

from dotenv import load_dotenv

load_dotenv()
CONFIG_PATH = os.getenv("TEMPLATE_SVC_CONFIG", "/app/config/config.json")
SERVICE_NAME = os.getenv("SERVICE_NAME", "template-service")
SERVICE_DESCRIPTION = os.getenv(
    "SERVICE_DESCRIPTION", "Temporary AutoPatch test service"
)
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
VERSION = os.getenv("VERSION", "0.1-beta")

MQTT_HOST = os.getenv("MQTT_HOST", "mosquitto")
MQTT_PORT = int(os.getenv("MQTT_PORT", 1883))
MQTT_INPUT_TOPIC = os.getenv("MQTT_INPUT_TOPIC", f"autopatch/{SERVICE_NAME}/in")
MQTT_OUTPUT_TOPIC = os.getenv("MQTT_OUTPUT_TOPIC", f"autopatch/{SERVICE_NAME}/out")

DOCKER_ENABLED = os.getenv("DOCKER_ENABLED", "false").lower() == "true"
TARGET_CONTAINER = os.getenv("TARGET_CONTAINER", "")
