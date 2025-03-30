import asyncio
import base64
import logging
import logging.config
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from typing import Final, List

from autopatchdatatypes import PatchRequest
from autopatchdatatypes import PatchResponse

# from autopatchdatatypes import PatchResponseStatus

from autopatchpubsub import MessageBrokerClient
from autopatchshared import get_current_timestamp, init_logging, load_config_as_json
from cloudevents.conversion import to_json
from cloudevents.http import CloudEvent
from llm_dispatch_config import LLMDispatchConfig

from openai import OpenAI

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_LLM_DISPATCH_CONFIG: Final[str] = "FUZZ_SVC_CONFIG"
config: LLMDispatchConfig

# before configuration is loaded, use the default logger
logger = logging.getLogger(__name__)


def load_config(json_config_full_path: str) -> LLMDispatchConfig:
    config = load_config_as_json(json_config_full_path, logger)
    return LLMDispatchConfig(**config)


async def request_patch(
    request: PatchRequest, message_broker_client: MessageBrokerClient
):
    pass


async def request_completion(
    sytem_prompt: str,
    user_prompt: str,
    model: str,
    temperature: float,
    top_p: str,
    max_tokens: int,
):
    pass


async def system_prompt():
    # return config.system_prompt
    raise NotImplementedError(
        "The system prompt function is not implemented. Please implement it."
    )


async def user_prompt():
    _goals = ""
    _return_format = ""
    _warnings = ""
    _context_window = ""

    # return f"{_goals} {_return_format} {_warnings} {_context_window}"
    raise NotImplementedError(
        "The user prompt function is not implemented. Please implement it."
    )


async def full_prompt():
    _system_prompt = await system_prompt()
    _user_prompt = await user_prompt()

    return f"{_system_prompt} {_user_prompt}"


async def request_completion_http(
    api_key: str,
    base_url: str,
    model: str,
    temperature: float,
    top_p: str,
    max_tokens: int,
    system_prompt: str,
    user_prompt: str,
    context_window: str,
    request_timeout: int,
    request_retries: int,
    request_delay: int,
    request_delay_max: int,
):
    _api_key = os.environ.get("OPENROUTERAI_API_KEY")
    client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=_api_key)

    completion = client.chat.completions.create(
        # model="google/gemini-2.0-flash-lite-preview-02-05:free",
        model="deepseek/deepseek-r1-zero:free",
        #   model="openai/gpt-4o-mini",
        messages=[
            {
                "role": "user",
                "content": str_source,
                #   "content": "What is the meaning of life?"
            }
        ],
    )

    print(completion.choices[0].message.content)
    pass


async def wrap_raw_response():
    pass


def handle_sigterm(signum, frame):
    pass


async def main():
    global config, logger

    models = [
        "google/gemini-2.0-flash-lite-preview-02-05:free",
        "openai/gpt-4o-mini:free",
        # "model": "gpt-3.5-turbo",
        # model="gpt-4o"
        "deepseek/deepseek-r1-zero:free",
    ]
    # _api_key = os.environ.get("OPENROUTERAI_API_KEY")
    # open_router_base_url = os.environ.get("OPENROUTERAI_BASE_URL")

    model_router_base_url = os.environ.get("MODEL_ROUTER_BASE_URL")
    model_router_api_key = os.environ.get("MODEL_ROUTER_API_KEY")

    # client = OpenAI(base_url="https://openrouter.ai/api/v1", api_key=_api_key)

    config_full_path = os.environ.get(CONST_LLM_DISPATCH_CONFIG)
    if not config_full_path:
        logger.error(
            f"Error: The environment variable {CONST_LLM_DISPATCH_CONFIG} is not set or is empty."
        )
        sys.exit(1)

    config = load_config(config_full_path)
    logger = init_logging(config.logging_config, config.appname)

    LLM_DISPATCH_START_TIMESTAMP: Final[str] = get_current_timestamp()
    pass


if __name__ == "__main__":
    # Run the event loop
    asyncio.run(main())
