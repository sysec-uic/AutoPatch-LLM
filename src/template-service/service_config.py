import os

from dotenv import load_dotenv

load_dotenv()

SERVICE_NAME = os.getenv("SERVICE_NAME", "template-servcie")
SERVICE_DESCRIPTION = os.getenv("SERVICE_DESCRIPTION", "Empty template service")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
CONFIG_PATH = os.getenv("TEMPLATE_SVC_CONFIG", "/app/config/config.json")
