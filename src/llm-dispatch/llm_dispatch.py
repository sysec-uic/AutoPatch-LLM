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
    """
    Load the configuration from a JSON file and instantiate a LLMDispatchConfig object.
    Parameters:
        json_config_full_path (str): The full file path to the JSON configuration file.
    Returns:
        LLMDispatchConfig: An instance of LLMDispatchConfig populated with the loaded configuration.
    Raises:
        Exception: Propagates any exceptions encountered during JSON loading or configuration parsing.
    """
    config = load_config_as_json(json_config_full_path, logger)
    return LLMDispatchConfig(**config)


# async def request_patch(
#     request: PatchRequest, message_broker_client: MessageBrokerClient
# ):
#     pass


async def read_file(file_full_path: str) -> str:
    """
    Asynchronously read the content of a file from a given full file path.
    Parameters:
        file_full_path (str): The full path of the file to be read.
    Returns:
        str: The content of the file if it exists; otherwise, an empty string is returned and an error is logged.

    """
    if not file_full_path:
        logger.error("File does not exist")
        return ""

    with open(file_full_path, "r") as f:
        return f.read()


# async def user_prompt(user_prompt_file_full_patch: str) -> str:
#     _goals = ""
#     _return_format = ""
#     _warnings = ""
#     _context_window = ""

#     return f"{_goals} {_return_format} {_warnings} {_context_window}"


async def full_prompt(system_prompt_full_path: str, user_prompt_full_path: str) -> str:
    _system_prompt = await read_file(system_prompt_full_path)
    _user_prompt = await read_file(user_prompt_full_path)

    _c_program_source_code_to_patch = await read_file(
        "/workspace/AutoPatch-LLM/src/llm-dispatch/data/prompts/dummy_c_file.c"
    )
    _separator = "\n---\n"

    return f"{_system_prompt} {_user_prompt} {_separator} {_c_program_source_code_to_patch}"


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

    async def generate(self, prompt: str) -> Dict:
        # Simulate an API call; replace with a real API call in production.
        response_text = f"API response for prompt '{prompt}' from {self.name}"  # TODO deletethis unused line
        response_text = await self.request_completion_http(
            api_key=self.api_key,
            base_url=self.endpoint,
            model=self.name,
            user_prompt=prompt,
        )
        return {"llm_name": self.name, "response": response_text}

    async def request_completion_http(
        self,
        api_key: str,
        base_url: str,
        model: str,
        user_prompt: str,
        # system_prompt: str,
        # temperature: float,
        # top_p: str,
        # max_tokens: int,
        # context_window: str,
        # request_timeout: int,
        # request_retries: int,
        # request_delay: int,
        # request_delay_max: int,
    ) -> str:
        # _api_key = os.environ.get("OPENROUTERAI_API_KEY")
        _api_key = api_key
        client = OpenAI(base_url=base_url, api_key=_api_key)

        completion = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "user",
                    "content": user_prompt,
                }
            ],
        )

        # TODO handle out of quota errors here

        completion = completion.choices[0].message.content
        logger.info(f"Completion: {completion}")

        return completion if completion else "No response"


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
    async def generate(self, prompt: str) -> List[Dict]:
        """Generate responses from all registered LLMs based on the prompt."""
        pass


# Concrete strategy for API-based LLMs.
class ApiLLMStrategy(LLMStrategy):
    def __init__(self):
        self.llms: List[ApiLLM] = []

    def register(self, llm: ApiLLM):
        self.llms.append(llm)

    async def generate(self, prompt: str) -> List[Dict]:
        responses = []
        for llm in self.llms:
            responses.append(await llm.generate(prompt))
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
        self.active_strategy: LLMStrategy

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

    async def generate(self, prompt: str) -> List[Dict]:
        """
        Dispatch the prompt to the active strategy and return the structured responses.
        """
        if not self.active_strategy:
            raise Exception(
                "No active strategy set. Please set a strategy using set_strategy()."
            )
        return await self.active_strategy.generate(prompt)


async def init_llm_client(
    models: List[str], model_router_api_key: str, model_router_base_url
) -> LLMClient:
    client = LLMClient()

    # Create strategy instances.
    api_strategy = ApiLLMStrategy()
    in_memory_strategy = InMemoryLLMStrategy()

    # Register LLMs with their respective strategies.
    len_models = len(models)
    for i in range(len_models):
        api_strategy.register
        api_strategy.register(
            ApiLLM(
                name=models[i],
                api_key=model_router_api_key,
                endpoint=model_router_base_url,
            )
        )

    # TODO not yet implemented
    in_memory_strategy.register(InMemoryLLM(name="LocalModel", model="dummy_model"))

    # Register strategies with the client.
    client.register_strategy("api", api_strategy)
    client.register_strategy("in_memory", in_memory_strategy)

    return client


async def main():
    global config, logger

    config_full_path = os.environ.get(CONST_LLM_DISPATCH_CONFIG)

    if not config_full_path:
        logger.error(
            f"Error: The environment variable {CONST_LLM_DISPATCH_CONFIG} is not set or is empty."
        )
        sys.exit(1)

    config = load_config(config_full_path)
    logger = init_logging(config.logging_config, config.appName)

    LLM_DISPATCH_START_TIMESTAMP: Final[str] = get_current_timestamp()

    models = [
        "openai/gpt-4o-mini:free",
        "deepseek/deepseek-r1-zero:free",
        "google/gemini-2.5-pro-exp-03-25:free",
    ]

    model_router_base_url = os.environ.get("MODEL_ROUTER_BASE_URL", "")
    model_router_api_key = os.environ.get("OPENROUTERAI_API_KEY", "")

    client: LLMClient = await init_llm_client(
        models, model_router_api_key, model_router_base_url
    )

    prompt: Final[str] = await full_prompt(
        config.system_prompt_full_path, config.user_prompt_full_path
    )

    # Set active strategy at runtime.
    client.set_strategy("api")  # Change to "in_memory" to use the in-memory strategy.

    responses = await client.generate(prompt)
    for response in responses:
        logger.info(f"LLM: {response['llm_name']}\nResponse: {response['response']}\n")

    LLM_DISPATCH_END_TIMESTAMP: Final[str] = get_current_timestamp()
    time_delta = datetime.fromisoformat(
        LLM_DISPATCH_END_TIMESTAMP
    ) - datetime.fromisoformat(LLM_DISPATCH_START_TIMESTAMP)
    logger.info(f"Total Processing Time Elapsed: {time_delta}")
    logger.info("Processing complete, exiting.")
    exit(0)


if __name__ == "__main__":
    # Run the event loop
    asyncio.run(main())
