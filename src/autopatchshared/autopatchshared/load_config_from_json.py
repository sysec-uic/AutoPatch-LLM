import json
import logging
import sys


def load_config_as_json(config_full_path: str, logger: logging.Logger) -> dict:
    """
    Load the configuration from a JSON file.  Does not support loading config from a YAML file.
    """
    if not config_full_path:
        logger.error(
            "Error: The 'json_config_full_path' parameter is not set or is empty."
        )
    try:
        # Open the file with UTF-8 encoding
        with open(config_full_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(f"Error: The config file at '{config_full_path}' was not found.")
        sys.exit(1)
    except UnicodeDecodeError as e:
        logger.error(
            f"Error: The config file at '{config_full_path}' is not a valid UTF-8 text file: {e}"
        )
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(
            f"Error: The config file at '{config_full_path}' contains invalid JSON: {e}"
        )
        sys.exit(1)
    except Exception as e:
        logger.error(
            f"Error: An unexpected error occurred while loading the config file: {e}"
        )
        sys.exit(1)

    return config
