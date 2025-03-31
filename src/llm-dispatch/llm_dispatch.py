from abc import ABC, abstractmethod
from typing import List, Dict
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

# from autopatchdatatypes import PatchRequest
# from autopatchdatatypes import PatchResponse

# from autopatchdatatypes import PatchResponseStatus

from autopatchpubsub import MessageBrokerClient
from autopatchshared import get_current_timestamp, init_logging, load_config_as_json
from cloudevents.conversion import to_json
from cloudevents.http import CloudEvent
from llm_dispatch_config import LLMDispatchConfig

from openai import OpenAI

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_LLM_DISPATCH_CONFIG: Final[str] = "LLM_DISPATCH_CONFIG"
config: LLMDispatchConfig

# before configuration is loaded, use the default logger
logger = logging.getLogger(__name__)


def load_config(json_config_full_path: str) -> LLMDispatchConfig:
    config = load_config_as_json(json_config_full_path, logger)
    return LLMDispatchConfig(**config)


# async def request_patch(
#     request: PatchRequest, message_broker_client: MessageBrokerClient
# ):
#     pass


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
    # _api_key = os.environ.get("OPENROUTERAI_API_KEY")
    _api_key = api_key
    client = OpenAI(base_url=base_url, api_key=_api_key)

    completion = client.chat.completions.create(
        # model="google/gemini-2.0-flash-lite-preview-02-05:free",
        # model="deepseek/deepseek-r1-zero:free",
        #   model="openai/gpt-4o-mini",
        model=model,
        messages=[
            {
                "role": "user",
                "content": user_prompt,
                #   "content": "What is the meaning of life?"
            }
        ],
    )

    completion = completion.choices[0].message.content
    logger.info(f"Completion: {completion}")
    return completion


async def wrap_raw_response():
    pass


def handle_sigterm(signum, frame):
    pass


# Base interface for any LLM implementation.
class BaseLLM(ABC):
    @abstractmethod
    def generate(self, prompt: str) -> Dict:
        """
        Generate a response based on the given prompt.
        Returns a dictionary containing:
            - "llm_name": Name of the LLM.
            - "response": The generated text response.
        """
        pass


# Concrete LLM implementations.
class ApiLLM(BaseLLM):
    def __init__(self, name: str, api_key: str, endpoint: str):
        self.name = name
        self.api_key = api_key
        self.endpoint = endpoint

    def generate(self, prompt: str) -> Dict:
        # Simulate an API call; replace with a real API call in production.
        response_text = f"API response for prompt '{prompt}' from {self.name}"
        return {"llm_name": self.name, "response": response_text}


class InMemoryLLM(BaseLLM):
    def __init__(self, name: str, model):
        self.name = name
        self.model = model  # Could be a loaded model in a real scenario.

    def generate(self, prompt: str) -> Dict:
        # Simulate in-memory generation; replace with a real call in production.
        response_text = f"In-memory response for prompt '{prompt}' from {self.name}"
        return {"llm_name": self.name, "response": response_text}


# Strategy interface for generating responses from a collection of LLMs.
class LLMStrategy(ABC):
    @abstractmethod
    def register(self, llm: BaseLLM):
        """Register an LLM with this strategy."""
        pass

    @abstractmethod
    def generate(self, prompt: str) -> List[Dict]:
        """Generate responses from all registered LLMs based on the prompt."""
        pass


# Concrete strategy for API-based LLMs.
class ApiLLMStrategy(LLMStrategy):
    def __init__(self):
        self.llms: List[ApiLLM] = []

    def register(self, llm: ApiLLM):
        self.llms.append(llm)

    def generate(self, prompt: str) -> List[Dict]:
        responses = []
        for llm in self.llms:
            responses.append(llm.generate(prompt))
        return responses


# Concrete strategy for in-memory LLMs.
class InMemoryLLMStrategy(LLMStrategy):
    def __init__(self):
        self.llms: List[InMemoryLLM] = []

    def register(self, llm: InMemoryLLM):
        self.llms.append(llm)

    def generate(self, prompt: str) -> List[Dict]:
        responses = []
        for llm in self.llms:
            responses.append(llm.generate(prompt))
        return responses


# Facade client that uses a strategy to dispatch the prompt.
class LLMClient:
    def __init__(self):
        # Mapping of strategy names to strategy instances.
        self.strategies: Dict[str, LLMStrategy] = {}
        self.active_strategy: LLMStrategy = None

    def register_strategy(self, name: str, strategy: LLMStrategy):
        """
        Register a strategy instance with a given name.
        """
        self.strategies[name] = strategy

    def set_strategy(self, name: str):
        """
        Set the active strategy to be used for generating responses.
        """
        if name in self.strategies:
            self.active_strategy = self.strategies[name]
        else:
            raise ValueError(f"Strategy '{name}' is not registered.")

    def generate(self, prompt: str) -> List[Dict]:
        """
        Dispatch the prompt to the active strategy and return the structured responses.
        """
        if not self.active_strategy:
            raise Exception(
                "No active strategy set. Please set a strategy using set_strategy()."
            )
        return self.active_strategy.generate(prompt)


async def main():
    global config, logger

    # "model": "gpt-3.5-turbo",
    # model="gpt-4o"
    models = [
        "google/gemini-2.0-flash-lite-preview-02-05:free",
        "openai/gpt-4o-mini:free",
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
    # Example usage:
    client = LLMClient()

    # Create strategy instances.
    api_strategy = ApiLLMStrategy()
    in_memory_strategy = InMemoryLLMStrategy()

    # Register LLMs with their respective strategies.
    api_strategy.register(
        ApiLLM(name="OpenAI", api_key="dummy_key", endpoint="https://api.openai.com/v1")
    )
    in_memory_strategy.register(InMemoryLLM(name="LocalModel", model="dummy_model"))

    # Register strategies with the client.
    client.register_strategy("api", api_strategy)
    client.register_strategy("in_memory", in_memory_strategy)

    # Set active strategy at runtime.
    client.set_strategy("api")  # Change to "in_memory" to use the in-memory strategy.
    prompt = "What is the capital of France?"
    responses = client.generate(prompt)
    for response in responses:
        print(f"LLM: {response['llm_name']}\nResponse: {response['response']}\n")

    # Run the event loop
    asyncio.run(main())
