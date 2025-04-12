import asyncio
import base64
import json
import logging
import os
import re
import sys
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, Final, List

from autopatchdatatypes import CpgScanResult, PatchResponse, TransformerMetadata
from autopatchpubsub import MessageBrokerClient
from autopatchshared import get_current_timestamp, init_logging, load_config_as_json
from cloudevents.conversion import to_json
from cloudevents.http import CloudEvent
from llm_dispatch_svc_config import LLMDispatchSvcConfig
from openai import OpenAI

# Global variables for the async queue and event loop.
async_cpg_scan_results_queue = asyncio.Queue()
event_loop: asyncio.AbstractEventLoop  # This will be set in main().


# from autopatchdatatypes import PatchRequest

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_LLM_DISPATCH_CONFIG: Final[str] = "LLM_DISPATCH_CONFIG"
config: LLMDispatchSvcConfig

# before configuration is loaded, use the default logger
logger = logging.getLogger(__name__)

executable_name_to_cpg_scan_result_map: Dict[str, CpgScanResult] = {}


async def map_cloud_event_as_cpg_scan_result(
    cpg_scan_result_cloud_event_str: str,
) -> CpgScanResult:
    """
    Maps a CloudEvent JSON string to a CpgScanResult object.

    Parameters:
        cloud_event (str): The CloudEvent JSON string.

    Returns:
        CpgScanResult: The mapped cpg scan result.
    """
    cloud_event: Dict = json.loads(cpg_scan_result_cloud_event_str)

    data = cloud_event.get("data", {})

    return CpgScanResult(
        executable_name=data.get("executable_name", ""),
        vulnerability_severity=data.get("vulnerability_severity", None),
        vulnerable_line_number=data.get("vulnerable_line_number", None),
        vulnerable_function=data.get("vulnerable_function", ""),
        vulnerability_description=data.get("vulnerability_description", ""),
    )


async def process_cpg_scan_result(cpg_scan_result: CpgScanResult) -> None:
    logger.info(f"Processing crash {cpg_scan_result}")
    # TODO evaluate if we can remove this check
    # if the crash executable is not in our executables base, then skip it
    if cpg_scan_result.executable_name not in executable_name_to_cpg_scan_result_map:
        logger.info(
            f"{cpg_scan_result.executable_name} not in set of compiled executables to process.. adding to map"
        )
        executable_name_to_cpg_scan_result_map[cpg_scan_result.executable_name] = (
            cpg_scan_result
        )
        logger.info(
            f"Current executable_name_cpg_scan_result_map: {executable_name_to_cpg_scan_result_map.items()}"
        )


async def process_item(item):
    """Asynchronously process an item."""
    cpg_scan_result = await map_cloud_event_as_cpg_scan_result(item)
    await process_cpg_scan_result(cpg_scan_result)


async def cpg_scan_result_consumer():
    """Continuously consume items from the async queue."""
    """
        this consumer coroutine waits for items from the asyncio.Queue
        and processes each with process_item(). This runs continuously in the event loop.
    """
    while True:
        item = await async_cpg_scan_results_queue.get()
        try:
            await process_item(item)
        finally:
            async_cpg_scan_results_queue.task_done()


def load_config(json_config_full_path: str) -> LLMDispatchSvcConfig:
    """
    Load the configuration from a JSON file and instantiate a LLMDispatchConfig object.
    Parameters:
        json_config_full_path (str): The full file path to the JSON configuration file.
    Returns:
        LLMDispatchConfig: An instance of LLMDispatchSvcConfig populated with the loaded configuration.
    Raises:
        Exception: Propagates any exceptions encountered during JSON loading or configuration parsing.
    """
    config = load_config_as_json(json_config_full_path, logger)
    return LLMDispatchSvcConfig(**config)


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
    _system_prompt: Final[str] = await read_file(system_prompt_full_path)
    _user_prompt: Final[str] = await read_file(user_prompt_full_path)

    _c_program_source_code_to_patch: Final[str] = await read_file(
        config.devonlyinputfilepath
    )
    _separator: Final[str] = "---"

    full_prompt: Final[str] = (
        f"{_system_prompt}\n{_user_prompt}\n{_separator}\n{_c_program_source_code_to_patch}"
    )
    logger.info(f"Full prompt: {full_prompt}")

    return full_prompt


def unwrap_raw_llm_response(raw_llm_response: str) -> str:
    """
    Extracts the content enclosed in code fences from a raw LLM response.
        This function searches for a Markdown code block in the input string,
        which may optionally begin with a language identifier (e.g., ```python).
        If such a block is found, the function extracts the content inside the code fences,
        trims any extra whitespace, and returns it. If no code fence is detected,
        the function returns the entire input string stripped of whitespace.
    Parameters:
        raw_llm_response (str): The raw LLM response that may include output wrapped in Markdown code fences.
    Returns:
        str: The extracted code content if a code fence is detected; otherwise, the trimmed raw response.
    """

    pattern = re.compile(r"```(?:\w+)?\s*([\s\S]*?)\s*```")
    match = pattern.search(raw_llm_response)
    if match:
        response = match.group(1).strip()
    else:
        response = raw_llm_response.strip()

    return response


def update_diff_filename(diff_str: str, new_filename: str) -> str:
    """
    Updates the diff header lines with the new C program filename.

    Parameters:
        diff_str (str): The input diff text.
        new_filename (str): The new C program filename to replace in the header.

    Returns:
        str: The updated diff text with replaced filenames in the first two lines.
    """
    # Split the diff text into individual lines.
    lines = diff_str.splitlines()

    # Check if there are at least two lines to process.
    if len(lines) >= 2:
        # Replace the filename in the first two lines.
        if lines[0].startswith("--- "):
            lines[0] = "--- " + new_filename
        if lines[1].startswith("+++ "):
            lines[1] = "+++ " + new_filename

    # Join the lines back together to form the updated diff text.
    return "\n".join(lines)


async def map_patchresponse_as_cloudevent(patch_response: PatchResponse) -> CloudEvent:
    """
    Maps a PatchRequest instance to a CloudEvent Occurence.

    Parameters:
        patch (PatchResponse): The patch response to be mapped.

    Returns:
        CloudEvent: The corresponding CloudEvent Occurence.
    """
    if patch_response is None or any(
        value is None
        for value in [
            patch_response.executable_name,
            patch_response.patch_snippet_base64,
            patch_response.TransformerMetadata,
            patch_response.status,
        ]
    ):
        logger.error("Invalid patch_response object or one of its values is None.")
        logger.debug(f"PatchResponse: {PatchResponse}")
        raise ValueError("Invalid patch_response object or one of its values is None.")

    metadata: TransformerMetadata = patch_response.TransformerMetadata
    if metadata is None or any(
        value is None
        for value in [
            metadata.llm_name,
            metadata.llm_version,
            metadata.llm_flavor,
        ]
    ):
        logger.error(
            "Invalid transformer_metadata object or one of its values is None."
        )
        logger.debug(f"TransformerMetadata: {metadata}")
        raise ValueError(
            "Invalid transformer_metadata object or one of its values is None."
        )

    attributes = {
        "type": "autopatch.patchresponse",
        "source": "autopatch.llm-dispatch-service",
        "subject": patch_response.executable_name,
        "time": get_current_timestamp(),
    }

    metadata = patch_response.TransformerMetadata

    data = {
        "executable_name": patch_response.executable_name,
        "patch_snippet_base64": patch_response.patch_snippet_base64,
        "TransformerMetadata": {
            "llm_name": metadata.llm_name,
            "llm_version": metadata.llm_version,
            "llm_flavor": metadata.llm_flavor,
        },
        "status": patch_response.status,
    }

    event = CloudEvent(attributes, data)
    return event


async def map_patchresponses_as_cloudevents(
    patch_responses: List[PatchResponse],
    concurrency_threshold: int = 10,
) -> List[CloudEvent]:
    """
    Map PatchResponse objects to CloudEvent objects.
    Parameters:
        patch_response (List[PatchResponse]): List of PatchResponse objects to be mapped.
    Returns:
        List[CloudEvent]: List of CloudEvent objects created from the PatchResponse objects.
    """
    if len(patch_responses) > concurrency_threshold:
        # Run in parallel
        tasks = [map_patchresponse_as_cloudevent(i) for i in patch_responses]
        results = await asyncio.gather(*tasks)
    else:
        # Run sequentially
        results = [await map_patchresponse_as_cloudevent(i) for i in patch_responses]

    return results


def on_consume_cpg_scan_result(cloud_event_str: str) -> None:
    """
    This is synchronous function that’s called from non‑async code.
    It uses the globally stored event_loop to schedule a call to
    async_queue.put_nowait in a thread‑safe manner.
    """
    logger.info(f"in on_consume_cpg_scan_result received {cloud_event_str}")
    # Schedule adding the event to the async queue.
    # Use call_soon_threadsafe so that this function can be safely called
    # from threads outside the event loop.
    global event_loop
    event_loop.call_soon_threadsafe(
        async_cpg_scan_results_queue.put_nowait, cloud_event_str
    )


async def produce_output(
    patch_response_output_topic: str,
    patch_responses: List[PatchResponse],
    message_broker_client: MessageBrokerClient,
    concurrency_threshold: int = 10,
) -> None:

    async def produce_event(event: CloudEvent) -> None:
        # flake8 flags the following as F821 because it doesn't recognize the global variable
        logger.debug(f"Producing on Topic: {patch_response_output_topic}")  # noqa: F821
        logger.debug(f"Producing CloudEvent: {event}")
        await message_broker_client.publish(
            patch_response_output_topic, to_json(event).decode("utf-8")  # noqa: F821
        )

    patch_response_cloud_events: List[CloudEvent] = (
        await map_patchresponses_as_cloudevents(patch_responses)
    )

    logger.info(f"Producing {len(patch_response_cloud_events)} CloudEvents.")
    if len(patch_response_cloud_events) > concurrency_threshold:
        # Run in parallel using asyncio.gather
        tasks = [produce_event(event) for event in patch_response_cloud_events]
        await asyncio.gather(*tasks)
    else:
        # Run sequentially
        for event in patch_response_cloud_events:
            await produce_event(event)


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
    def __init__(
        self,
        name: str,
        api_key: str,
        endpoint: str,
        temperature: float = 1,
        top_p: float = 1,
    ):
        self.name = name
        self.api_key = api_key
        self.endpoint = endpoint
        self.temperature = temperature
        self.top_p = top_p

    async def generate(self, prompt: str) -> Dict[str, str]:
        response_text = await self.request_completion_http(
            api_key=self.api_key,
            base_url=self.endpoint,
            model=self.name,
            user_prompt=prompt,
            temperature=self.temperature,
            top_p=self.top_p,
        )
        return {"llm_name": self.name, "response": response_text}

    async def request_completion_http(
        self,
        api_key: str,
        base_url: str,
        model: str,
        user_prompt: str,
        # system_prompt: str,
        temperature: float,
        top_p: float,
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
            temperature=temperature,
            top_p=top_p,
            messages=[
                {
                    "role": "user",
                    "content": user_prompt,
                }
            ],
        )

        # TODO handle out of quota errors here

        completion_str = ""
        try:
            completion_str = completion.choices[0].message.content
        except Exception as e:
            # TODO expand error handling
            logger.error(f"Error returned from Model Router API: {e}")

        logger.debug(f"Completion: {completion}")

        return completion_str if completion_str else "No response"


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
            logger.info("Waiting for 1.0 seconds to avoid triggering API rate limits.")
            await asyncio.sleep(1.0)
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

    async def generate(self, prompt: str) -> List[Dict[str, str]]:
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


async def create_patch_responses(
    raw_responses: List[Dict[str, str]],
    source_filename_or_program_name_under_consideration_unique_id: List[str],
    concurrency_threshold: int = 10,
) -> List[PatchResponse]:
    """
    Creates patch responses from the provided raw responses and their associated unique identifiers.
    Parameters:
        raw_responses (List[Dict[str, str]]): A list of dictionaries containing raw response data.
        source_filename_or_program_name_under_consideration_unique_id (List[str]):
            A list of unique identifiers corresponding to each raw response, such as source filenames
            or program names.
        concurrency_threshold (int, optional): The maximum number of raw responses to process
            sequentially. If the number of raw responses exceeds this threshold, processing is
            executed in parallel. Defaults to 10.
    Returns:
        List[PatchResponse]: A list of patch responses generated from the raw responses.
    """
    if len(raw_responses) > concurrency_threshold:
        # Run in parallel
        tasks = [
            create_patch_response(x[0], x[1])
            for x in zip(
                raw_responses,
                source_filename_or_program_name_under_consideration_unique_id,
            )
        ]
        results = await asyncio.gather(*tasks)
    else:
        # Run sequentially
        results = [
            await create_patch_response(x[0], x[1])
            for x in zip(
                raw_responses,
                source_filename_or_program_name_under_consideration_unique_id,
            )
        ]

    return results


async def create_patch_response(
    raw_response: Dict[str, str],
    source_filename_or_program_name_under_consideration_unique_id: str,
) -> PatchResponse:
    """
    Create a PatchRequest objects from the raw response.
    """
    name_id_str = source_filename_or_program_name_under_consideration_unique_id

    unwrapped_response = unwrap_raw_llm_response(raw_response["response"])
    updated_response = update_diff_filename(unwrapped_response, name_id_str)
    _llm_name = raw_response["llm_name"][
        raw_response["llm_name"].index("/") + 1 : raw_response["llm_name"].index(":")
    ]
    _llm_flavor = raw_response["llm_name"][: raw_response["llm_name"].index("/")]
    metadata: TransformerMetadata = TransformerMetadata(
        llm_name=_llm_name, llm_flavor=_llm_flavor, llm_version="not available"
    )
    return PatchResponse(
        name_id_str,
        base64.b64encode(updated_response.encode("utf-8")).decode("utf-8"),
        metadata,
        status="success",
    )


def init_message_broker(
    message_broker_host: str, message_broker_port: int, logger: logging.Logger
) -> MessageBrokerClient:
    """
    Initialize a MessageBrokerClient instance with the configured host, port, and logger settings.
    Returns:
        MessageBrokerClient: The configured MessageBrokerClient ready for use.
    """
    message_broker_client: Final[MessageBrokerClient] = MessageBrokerClient(
        message_broker_host,
        message_broker_port,
        logger,
    )
    return message_broker_client


async def main():
    global config, logger
    global event_loop

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
        "google/gemini-2.5-pro-exp-03-25:free",
        "deepseek/deepseek-r1-zero:free",
        "meta-llama/llama-3.3-70b-instruct:free",
        "mistralai/mistral-small-3.1-24b-instruct:free",
    ]

    model_router_base_url = os.environ.get("MODEL_ROUTER_BASE_URL", "CHANGE_ME")
    model_router_api_key = os.environ.get("MODEL_ROUTER_API_KEY", "CHANGE_ME")

    client: LLMClient = await init_llm_client(
        models, model_router_api_key, model_router_base_url
    )

    prompt: Final[str] = await full_prompt(
        config.system_prompt_full_path, config.user_prompt_full_path
    )

    # Set active strategy at runtime.
    client.set_strategy("api")  # Change to "in_memory" to use the in-memory strategy.

    dummy_filename = "dummy_c_file.c"

    event_loop = asyncio.get_running_loop()

    # Start the consumer coroutine as a background task.
    asyncio.create_task(cpg_scan_result_consumer())

    message_broker_client: Final[MessageBrokerClient] = init_message_broker(
        config.message_broker_host,
        config.message_broker_port,
        logger,
    )

    # subscribe to topic
    message_broker_client.consume(
        config.cpg_scan_result_input_topic, on_consume_cpg_scan_result
    )

    responses = await client.generate(prompt)
    patch_responses: List[PatchResponse] = await create_patch_responses(
        responses, [dummy_filename] * len(responses)
    )
    await produce_output(
        config.message_broker_topics["response"], patch_responses, message_broker_client
    )

    # LLM_DISPATCH_END_TIMESTAMP: Final[str] = get_current_timestamp()
    # time_delta = datetime.fromisoformat(
    #     LLM_DISPATCH_END_TIMESTAMP
    # ) - datetime.fromisoformat(LLM_DISPATCH_START_TIMESTAMP)
    # logger.info(f"Total Processing Time Elapsed: {time_delta}")
    # logger.info("Processing complete, exiting.")

    # TODO finish making event driven
    # Keep the program running indefinitely, waiting for more events.
    await asyncio.Future()  # This future will never complete.


if __name__ == "__main__":
    # Run the event loop
    asyncio.run(main())
