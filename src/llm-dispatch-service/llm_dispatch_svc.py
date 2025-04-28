from dataclasses import dataclass
import asyncio
import base64
import json
import logging
import os
import re
import sys
from abc import ABC, abstractmethod
from typing import Dict, Final, List, Set, Optional

import openai
from autopatchdatatypes import CpgScanResult, PatchResponse, TransformerMetadata
from autopatchpubsub import MessageBrokerClient
from autopatchshared import get_current_timestamp, init_logging, load_config_as_json
from cloudevents.conversion import to_json
from cloudevents.http import CloudEvent
from llm_dispatch_svc_config import LLMDispatchSvcConfig
from openai import OpenAI


async_cpg_scan_results_queue = asyncio.Queue()
event_loop: asyncio.AbstractEventLoop

CONST_LLM_DISPATCH_CONFIG: Final[str] = "LLM_DISPATCH_CONFIG"
config: LLMDispatchSvcConfig

logger = logging.getLogger(__name__)

executable_name_to_cpg_scan_result_map: Dict[str, CpgScanResult] = {}
CONST_NO_RESPONSE: Final[str] = "No response"
unreachable_models: Set[str] = set()


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

    # Ensure correct types are handled, providing defaults if necessary
    severity = data.get("vulnerability_severity")
    line_number = data.get("vulnerable_line_number")

    return CpgScanResult(
        executable_name=data.get("executable_name", ""),
        vulnerability_severity=float(severity) if severity is not None else 0.0,
        vulnerable_line_number=int(line_number) if line_number is not None else 0,
        vulnerable_function=data.get("vulnerable_function", ""),
        vulnerability_description=data.get("vulnerability_description", ""),
    )


async def process_cpg_scan_result(cpg_scan_result: CpgScanResult) -> None:
    # Store the result using the executable name as the key
    executable_name_to_cpg_scan_result_map[
        cpg_scan_result.executable_name.removesuffix(".c")
    ] = cpg_scan_result
    logger.info(
        f"Added/Updated CPG scan result for {cpg_scan_result.executable_name}. Map size: {len(executable_name_to_cpg_scan_result_map)}"
    )
    logger.debug(
        f"Current executable_name_cpg_scan_result_map keys: {list(executable_name_to_cpg_scan_result_map.keys())}"
    )


async def processcpg_scan_result_item(item):
    """Asynchronously process an item."""
    try:
        cpg_scan_result = await map_cloud_event_as_cpg_scan_result(item)
        await process_cpg_scan_result(cpg_scan_result)
    except json.JSONDecodeError:
        logger.error(f"Failed to decode JSON from item: {item}")
    except Exception as e:
        logger.error(f"Error processing CPG scan result item: {e}", exc_info=True)


async def cpg_scan_result_consumer():
    """Continuously consume items from the async queue."""
    """
        this consumer coroutine waits for items from the asyncio.Queue
        and processes each with process_item(). This runs continuously in the event loop.
    """
    while True:
        item = await async_cpg_scan_results_queue.get()
        try:
            await processcpg_scan_result_item(item)
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
    config_data = load_config_as_json(
        json_config_full_path, logger
    )  # Corrected function call
    return LLMDispatchSvcConfig(**config_data)


async def read_file(file_full_path: str) -> str:
    """
    Asynchronously read the content of a file from a given full file path.
    Parameters:
        file_full_path (str): The full path of the file to be read.
    Returns:
        str: The content of the file if it exists; otherwise, an empty string is returned and an error is logged.

    """
    if not file_full_path or not os.path.exists(file_full_path):
        logger.error(f"File does not exist or path is invalid: {file_full_path}")
        return ""
    # Use async file reading if available/needed, otherwise stick to sync for simplicity here
    try:
        with open(file_full_path, "r", encoding="utf-8") as f:
            return f.read()
    except Exception as e:
        logger.error(f"Error reading file {file_full_path}: {e}")
        return ""


def format_cpg_scan_context(cpg_context: CpgScanResult) -> str:
    """
    Formats the CpgScanResult object into a string suitable for prompt augmentation.

    Parameters:
        cpg_context (CpgScanResult): The CPG scan result object containing vulnerability details.

    Returns:
        str: A formatted string describing the vulnerability context.
    """
    if not cpg_context:
        return ""  # Return empty string if context is None

    context_str = (
        f"Vulnerability Context:\n"
        f"- Executable Name: {cpg_context.executable_name}\n"
        f"- Severity Score: {cpg_context.vulnerability_severity}\n"
        f"- Vulnerable Line: {cpg_context.vulnerable_line_number}\n"
        f"- Vulnerable Function: {cpg_context.vulnerable_function}\n"
        f"- Description: {cpg_context.vulnerability_description}\n"
    )
    return context_str


async def full_prompt(
    system_prompt_full_path: str,
    user_prompt_full_path: str,
    input_c_program_full_path: str,
    cpg_context: Optional[CpgScanResult] = None,
) -> str:
    """
    Constructs the full prompt by combining system prompt, user prompt, CPG context (if available),
    and the source code.

    Parameters:
        system_prompt_full_path (str): Path to the system prompt file.
        user_prompt_full_path (str): Path to the user prompt file.
        input_c_program_full_path (str): Path to the C source code file.
        cpg_context (Optional[CpgScanResult]): The vulnerability context from CPG scan.

    Returns:
        str: The fully constructed prompt.
    """
    _system_prompt: Final[str] = await read_file(system_prompt_full_path)
    _user_prompt: Final[str] = await read_file(user_prompt_full_path)
    _c_program_source_code_to_patch: Final[str] = await read_file(
        input_c_program_full_path
    )

    # Format the CPG context if it's provided
    _formatted_cpg_context: str = ""
    if cpg_context:
        _formatted_cpg_context = format_cpg_scan_context(cpg_context)
        logger.info(
            f"Augmenting prompt with CPG context for {cpg_context.executable_name}"
        )

    _separator: Final[str] = "Here is the source code (starting at line 1):\n---\n"

    # Combine all parts, including the CPG context if available
    # Place context after user prompt but before the code separator
    full_prompt_parts = [
        _system_prompt,
        _user_prompt,
        _formatted_cpg_context if _formatted_cpg_context else "",  # Add context here
        _separator,
        _c_program_source_code_to_patch,
    ]
    # Filter out empty strings that might result from missing files or context
    full_prompt: Final[str] = "\n".join(part for part in full_prompt_parts if part)

    logger.info(
        f"Created Full Prompt for: {input_c_program_full_path}. View Full Prompt in Debug log"
    )
    logger.debug(
        f"Full prompt:\n{full_prompt}"
    )  # Added newline for readability in logs

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


async def map_patchresponse_as_cloudevent(patch_response: PatchResponse) -> CloudEvent:
    """
    Maps a PatchRequest instance to a CloudEvent Occurence.

    Parameters:
        patch (PatchResponse): The patch response to be mapped.

    Returns:
        CloudEvent: The corresponding CloudEvent Occurence.
    """
    if patch_response is None:
        logger.error("Invalid patch_response object: cannot be None.")
        raise ValueError("Invalid patch_response object: cannot be None.")

    # Simplified check using a helper or direct access if structure is guaranteed
    required_patch_attrs = [
        "executable_name",
        "patch_snippet_base64",
        "TransformerMetadata",
        "status",
    ]
    if any(
        getattr(patch_response, attr, None) is None for attr in required_patch_attrs
    ):
        logger.error(
            f"Invalid patch_response object or one of its required values is None. Object: {patch_response}"
        )
        raise ValueError(
            "Invalid patch_response object or one of its required values is None."
        )

    metadata: TransformerMetadata = patch_response.TransformerMetadata
    required_metadata_attrs = ["llm_name", "llm_version", "llm_flavor"]
    if metadata is None or any(
        getattr(metadata, attr, None) is None for attr in required_metadata_attrs
    ):
        logger.error(
            f"Invalid transformer_metadata object or one of its values is None. Metadata: {metadata}"
        )
        raise ValueError(
            "Invalid transformer_metadata object or one of its values is None."
        )

    attributes = {
        "type": "autopatch.patchresponse",
        "source": "autopatch.llm-dispatch-service",
        "subject": patch_response.executable_name,
        "time": get_current_timestamp(),
    }

    # Ensure metadata is correctly structured in the data payload
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
    tasks = [map_patchresponse_as_cloudevent(pr) for pr in patch_responses]

    if len(patch_responses) > concurrency_threshold:
        # Run in parallel using asyncio.gather
        results = await asyncio.gather(*tasks, return_exceptions=True)
    else:
        # Run sequentially
        results = []
        for task in tasks:
            try:
                result = await task
                results.append(result)
            except Exception as e:
                # Log error and append exception or handle as needed
                logger.error(f"Error mapping patch response to CloudEvent: {e}")
                results.append(e)  # Or append None, or filter out errors

    # Filter out potential exceptions if they were gathered
    return [res for res in results if isinstance(res, CloudEvent)]


def on_consume_cpg_scan_result(cloud_event_str: str) -> None:
    """
    This is synchronous function that’s called from non‑async code.
    It uses the globally stored event_loop to schedule a call to
    async_queue.put_nowait in a thread‑safe manner.
    """
    logger.info(f"Received CPG scan result message, scheduling for async processing.")
    logger.debug(f"Raw CPG scan result message: {cloud_event_str}")
    # Schedule adding the event to the async queue.
    # Use call_soon_threadsafe so that this function can be safely called
    # from threads outside the event loop.
    global event_loop
    if event_loop and event_loop.is_running():
        event_loop.call_soon_threadsafe(
            async_cpg_scan_results_queue.put_nowait, cloud_event_str
        )
    else:
        logger.error(
            "Event loop not available or not running. Cannot schedule CPG scan result processing."
        )


async def produce_output(
    patch_response_output_topic: str,
    patch_responses: List[PatchResponse],
    message_broker_client: MessageBrokerClient,
    concurrency_threshold: int = 10,
) -> None:

    async def produce_event(event: CloudEvent) -> None:
        try:
            logger.debug(f"Producing on Topic: {patch_response_output_topic}")
            logger.debug(f"Producing CloudEvent: {event}")
            event_json = to_json(event).decode("utf-8")
            await message_broker_client.publish(patch_response_output_topic, event_json)
            logger.info(
                f"Successfully produced CloudEvent for {event['subject']} to {patch_response_output_topic}"
            )
        except Exception as e:
            logger.error(
                f"Failed to produce CloudEvent to {patch_response_output_topic}: {e}",
                exc_info=True,
            )

    patch_response_cloud_events: List[CloudEvent] = (
        await map_patchresponses_as_cloudevents(patch_responses, concurrency_threshold)
    )

    if not patch_response_cloud_events:
        logger.warning(
            "No valid CloudEvents generated from patch responses. Nothing to produce."
        )
        return

    logger.info(f"Producing {len(patch_response_cloud_events)} CloudEvents.")
    tasks = [produce_event(event) for event in patch_response_cloud_events]

    if len(patch_response_cloud_events) > concurrency_threshold:
        # Run in parallel using asyncio.gather
        await asyncio.gather(*tasks)
    else:
        # Run sequentially
        for task in tasks:
            await task


# Base interface for any LLM implementation.
class BaseLLM(ABC):
    @abstractmethod
    async def generate(self, prompt: str) -> Dict:  # Made generate async
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
        # Initialize OpenAI client once per instance
        self.client = OpenAI(base_url=self.endpoint, api_key=self.api_key)

    async def generate(self, prompt: str) -> Dict[str, str]:
        response_text = await self.request_completion_http(
            # No need to pass client details again, use self.client
            model=self.name,
            user_prompt=prompt,
            temperature=self.temperature,
            top_p=self.top_p,
        )
        return {"llm_name": self.name, "response": response_text}

    async def request_completion_http(
        self,
        model: str,
        user_prompt: str,
        temperature: float,
        top_p: float,
    ) -> str:
        # Use the instance's client
        # client = OpenAI(base_url=base_url, api_key=api_key) # Removed, use self.client

        try:
            # Here we concatenate the full prompt as the user prompt.
            # This if fine as we are not performing few shot or chain of thought prompting
            completion = await asyncio.to_thread(  # Use to_thread for blocking I/O
                self.client.chat.completions.create,
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
            completion_str = completion.choices[0].message.content

        except openai.NotFoundError as e:
            # Models sometimes get deprecated
            logger.error(f"Route provider for Model not found: {model}. Error: {e}")
            unreachable_models.add(model)
            return CONST_NO_RESPONSE
        except openai.APIConnectionError as e:
            logger.error(f"API connection error for model {model}: {e}")
            unreachable_models.add(model)  # Mark as potentially unreachable
            return CONST_NO_RESPONSE
        except openai.RateLimitError as e:
            logger.error(f"Rate limit exceeded for model {model}: {e}")
            # Consider retry logic here or marking as temporarily unavailable
            unreachable_models.add(model)  # Mark as potentially unreachable
            return CONST_NO_RESPONSE
        except Exception as e:
            logger.error(
                f"Error returned from Model Router API for model {model}: {e}",
                exc_info=True,
            )
            unreachable_models.add(model)  # Mark as potentially unreachable
            return CONST_NO_RESPONSE

        logger.info(
            f"Completion received from Model Router API for {model}. Full completion in Debug Log"
        )
        logger.debug(f"Completion for {model}: {completion}")

        return completion_str if completion_str else CONST_NO_RESPONSE


class InMemoryLLM(BaseLLM):
    def __init__(self, name: str, model):
        self.name = name
        self.model = model  # Could be a loaded model in a real scenario.

    async def generate(self, prompt: str) -> Dict:  # Made async
        # Simulate in-memory generation; replace with a real call in production.
        # If the actual model call is blocking, use asyncio.to_thread
        await asyncio.sleep(0.1)  # Simulate async work
        response_text = f"In-memory response for prompt '{prompt}' from {self.name}"
        return {"llm_name": self.name, "response": response_text}


# Strategy interface for generating responses from a collection of LLMs.
class LLMStrategy(ABC):
    @abstractmethod
    def register(self, llm: BaseLLM):
        """Register an LLM with this strategy."""
        pass

    @abstractmethod
    async def generate(self, prompt: str) -> List[Dict]:  # Made async
        """Generate responses from all registered LLMs based on the prompt."""
        pass


# Concrete strategy for API-based LLMs.
class ApiLLMStrategy(LLMStrategy):
    def __init__(self):
        self.llms: List[ApiLLM] = []

    def register(self, llm: ApiLLM):
        if isinstance(llm, ApiLLM):
            self.llms.append(llm)
        else:
            logger.warning(
                f"Attempted to register non-ApiLLM ({type(llm)}) with ApiLLMStrategy. Skipping."
            )

    async def generate(self, prompt: str) -> List[Dict]:  # Made async
        tasks = []
        for llm in self.llms:
            if llm.name not in unreachable_models:
                tasks.append(llm.generate(prompt))  # llm.generate is now async
            else:
                logger.warning(f"Skipping unreachable model: {llm.name}")

        responses = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results, filter out exceptions or handle them
        final_responses = []
        for i, response in enumerate(responses):
            original_llm_name = self.llms[i].name  # Assuming order is preserved
            if isinstance(response, Exception):
                logger.error(
                    f"Error generating response from {original_llm_name}: {response}"
                )
                # Optionally add a placeholder response or mark as failed
            elif isinstance(response, dict):
                final_responses.append(response)
            else:
                logger.warning(
                    f"Unexpected result type from {original_llm_name}: {type(response)}"
                )

        return final_responses


# Concrete strategy for in-memory LLMs.
class InMemoryLLMStrategy(LLMStrategy):
    def __init__(self):
        self.llms: List[InMemoryLLM] = []

    def register(self, llm: InMemoryLLM):
        if isinstance(llm, InMemoryLLM):
            self.llms.append(llm)
        else:
            logger.warning(
                f"Attempted to register non-InMemoryLLM ({type(llm)}) with InMemoryLLMStrategy. Skipping."
            )

    async def generate(self, prompt: str) -> List[Dict]:  # Made async
        tasks = [llm.generate(prompt) for llm in self.llms]  # generate is now async
        responses = await asyncio.gather(
            *tasks, return_exceptions=True
        )  # Handle potential errors

        # Process results, filter out exceptions or handle them
        final_responses = []
        for i, response in enumerate(responses):
            original_llm_name = self.llms[i].name  # Assuming order is preserved
            if isinstance(response, Exception):
                logger.error(
                    f"Error generating response from {original_llm_name}: {response}"
                )
            elif isinstance(response, dict):
                final_responses.append(response)
            else:
                logger.warning(
                    f"Unexpected result type from {original_llm_name}: {type(response)}"
                )

        return final_responses


# Facade client that uses a strategy to dispatch the prompt.
class LLMClient:
    def __init__(self):
        # Mapping of strategy names to strategy instances.
        self.strategies: Dict[str, LLMStrategy] = {}
        # Initialize active_strategy to None or a default
        self.active_strategy: Optional[LLMStrategy] = None  # Made optional

    def register_strategy(self, name: str, strategy: LLMStrategy):
        """
        Register a strategy instance with a given name.
        """
        self.strategies[name] = strategy
        logger.info(f"Registered LLM strategy: {name}")

    def set_strategy(self, name: str):
        """
        Set the active strategy to be used for generating responses.
        """
        if name in self.strategies:
            self.active_strategy = self.strategies[name]
            logger.info(f"Set active LLM strategy to: {name}")
        else:
            logger.error(f"Strategy '{name}' is not registered.")
            raise ValueError(f"Strategy '{name}' is not registered.")

    async def generate(self, prompt: str) -> List[Dict[str, str]]:  # Made async
        """
        Dispatch the prompt to the active strategy and return the structured responses.
        """
        if not self.active_strategy:
            logger.error(
                "No active strategy set. Please set a strategy using set_strategy()."
            )
            # Raise specific exception
            raise RuntimeError(
                "No active strategy set. Please set a strategy using set_strategy()."
            )
        # active_strategy.generate is now async
        return await self.active_strategy.generate(prompt)


async def init_llm_client(
    models: List[str],
    model_router_api_key: str,
    model_router_base_url: str,  # Added type hint
) -> LLMClient:
    """
    Initialize and configure an LLMClient with API and in-memory strategies.
    This asynchronous function sets up an LLMClient by creating instances of both API and in-memory
    strategies. It registers each model provided in the `models` list with the API strategy using the
    specified API key and endpoint. Additionally, a placeholder in-memory model is registered with the
    in-memory strategy which provides for forward compatibility with future implementations.

    Parameters:
        models (List[str]): A list of model names to be registered with the API strategy.
        model_router_api_key (str): The API key for accessing the model router service.
        model_router_base_url (str): The base URL for the model router service endpoint.
    Returns:
        LLMClient: A configured LLMClient instance with the registered strategies.
    """
    if not all([models, model_router_api_key, model_router_base_url]):
        logger.error("Missing required parameters for LLM client initialization.")
        raise ValueError("Models list, API key, and base URL are required.")

    client = LLMClient()

    # Create strategy instances.
    api_strategy = ApiLLMStrategy()
    in_memory_strategy = InMemoryLLMStrategy()

    # Register LLMs with their respective strategies.
    # len_models = len(models) # Not needed directly
    logger.info(f"Registering {len(models)} API models...")
    for model_name in models:
        # api_strategy.register # This line did nothing
        api_strategy.register(
            ApiLLM(
                name=model_name,
                api_key=model_router_api_key,
                endpoint=model_router_base_url,
                # Consider making temperature/top_p configurable per model if needed
            )
        )
    logger.info("API models registered.")

    # TODO not yet implemented - Register in-memory models if needed
    logger.info("Registering placeholder in-memory model...")
    in_memory_strategy.register(InMemoryLLM(name="LocalModel", model="dummy_model"))
    logger.info("In-memory model registered.")

    # Register strategies with the client.
    client.register_strategy("api", api_strategy)
    client.register_strategy("in_memory", in_memory_strategy)

    # Optionally set a default strategy here
    # client.set_strategy("api")

    return client


# --- create_patch_responses needs update to handle concurrency correctly ---
async def create_patch_response(
    raw_response: Dict[str, str],
    program_name_under_consideration_uid: str,
) -> PatchResponse:
    """
    Create a PatchResponse object from a single raw LLM response.
    """
    # Validate raw_response structure
    if (
        not isinstance(raw_response, dict)
        or "response" not in raw_response
        or "llm_name" not in raw_response
    ):
        logger.error(f"Invalid raw_response format: {raw_response}")
        # Return a failed PatchResponse or raise an error
        # For now, creating a failed response
        metadata = TransformerMetadata(
            llm_name="unknown", llm_flavor="unknown", llm_version="unknown"
        )
        return PatchResponse(
            program_name_under_consideration_uid.removesuffix(".c"),
            "",  # No patch snippet
            metadata,
            status="fail",
        )

    unwrapped_response = unwrap_raw_llm_response(
        raw_response.get("response", CONST_NO_RESPONSE)
    )
    # updated_response = unwrapped_response # Redundant assignment

    _llm_name_full = raw_response.get("llm_name", "unknown/unknown")

    # Improved parsing for llm name and flavor
    try:
        _llm_flavor, _llm_specific = _llm_name_full.split("/", 1)
        # Further split specific name from potential tag/version if needed
        if ":" in _llm_specific:
            _llm_name = _llm_specific.split(":", 1)[0]
        else:
            _llm_name = _llm_specific
    except ValueError:
        logger.warning(
            f"Could not parse LLM name/flavor from '{_llm_name_full}'. Using defaults."
        )
        _llm_name = _llm_name_full  # Use full name if parsing fails
        _llm_flavor = "unknown"

    metadata: TransformerMetadata = TransformerMetadata(
        llm_name=_llm_name,
        llm_flavor=_llm_flavor,
        llm_version="not available",  # Consider extracting version if present
    )

    # Encode the unwrapped response
    patch_snippet_base64 = base64.b64encode(unwrapped_response.encode("utf-8")).decode(
        "utf-8"
    )

    # Determine status based on whether a meaningful response was generated
    status = (
        "success"
        if unwrapped_response != CONST_NO_RESPONSE and unwrapped_response
        else "fail"
    )

    return PatchResponse(
        program_name_under_consideration_uid.removesuffix(
            ".c"
        ),  # Ensure correct executable name
        patch_snippet_base64,
        metadata,
        status=status,
    )


async def create_patch_responses(
    raw_responses: List[Dict[str, str]],
    source_filename_or_program_name_under_consideration_unique_id: str,  # Changed: Expect single ID per call now
    concurrency_threshold: int = 10,  # Concurrency applies to LLM calls, not this mapping
) -> List[PatchResponse]:
    """
    Creates patch responses from a list of raw responses for a SINGLE source file/program.

    Parameters:
        raw_responses (List[Dict[str, str]]): A list of dictionaries containing raw response data from different LLMs for the same input.
        source_filename_or_program_name_under_consideration_unique_id (str):
            The unique identifier (e.g., source filename) corresponding to ALL raw responses in the list.
        concurrency_threshold (int, optional): This parameter is less relevant here as mapping is usually fast. Kept for signature consistency but not used for concurrency logic within this function.

    Returns:
        List[PatchResponse]: A list of patch responses generated from the raw responses.
    """
    if not isinstance(raw_responses, list):
        logger.error("raw_responses must be a list.")
        return []

    tasks = [
        create_patch_response(
            response, source_filename_or_program_name_under_consideration_unique_id
        )
        for response in raw_responses
    ]

    # Mapping is generally lightweight, asyncio.gather might add overhead for small lists.
    # Decide based on typical list size or profile if needed.
    # Running sequentially for simplicity unless proven bottleneck.
    results = []
    for task in tasks:
        # Since create_patch_response is now async (due to potential future async ops)
        result = await task
        results.append(result)

    # results = await asyncio.gather(*tasks) # If parallelization is desired

    return results


def init_message_broker(
    message_broker_host: str, message_broker_port: int, logger: logging.Logger
) -> MessageBrokerClient:
    """
    Initialize a MessageBrokerClient instance with the configured host, port, and logger settings.
    Returns:
        MessageBrokerClient: The configured MessageBrokerClient ready for use.
    """
    logger.info(
        f"Initializing Message Broker Client for {message_broker_host}:{message_broker_port}"
    )
    try:
        message_broker_client: Final[MessageBrokerClient] = MessageBrokerClient(
            message_broker_host,
            message_broker_port,
            logger,
        )
        # Consider adding a connection check/ping here if the client supports it
        logger.info("Message Broker Client initialized.")
        return message_broker_client
    except Exception as e:
        logger.error(f"Failed to initialize Message Broker Client: {e}", exc_info=True)
        # Depending on requirements, either raise the exception or handle gracefully
        raise  # Re-raise the exception to indicate failure


async def main():
    global config, logger
    global event_loop
    global executable_name_to_cpg_scan_result_map  # Ensure map is accessible

    # --- Configuration Loading ---
    config_full_path = os.environ.get(CONST_LLM_DISPATCH_CONFIG)
    if not config_full_path:
        # Use default logger before config is loaded
        logging.basicConfig(level=logging.INFO)
        logging.error(
            f"Error: The environment variable {CONST_LLM_DISPATCH_CONFIG} is not set or is empty."
        )
        sys.exit(1)

    try:
        config = load_config(config_full_path)
        logger = init_logging(config.logging_config, config.appName)
        logger.info(f"Configuration loaded successfully from {config_full_path}")
    except Exception as e:
        logging.error(
            f"Failed to load configuration or initialize logging: {e}", exc_info=True
        )
        sys.exit(1)

    # --- Environment Variable Checks ---
    model_router_base_url = os.environ.get("MODEL_ROUTER_BASE_URL")
    model_router_api_key = os.environ.get("MODEL_ROUTER_API_KEY")

    if not model_router_base_url or model_router_base_url == "CHANGE_ME":
        logger.error(
            "MODEL_ROUTER_BASE_URL environment variable not set or is default."
        )
        sys.exit(1)
    if not model_router_api_key or model_router_api_key == "CHANGE_ME":
        logger.error("MODEL_ROUTER_API_KEY environment variable not set or is default.")
        sys.exit(1)

    # --- Initialization ---
    try:
        event_loop = asyncio.get_running_loop()

        models = config.models
        logger.info(f"Configured Models: {models}")

        client: LLMClient = await init_llm_client(
            models, model_router_api_key, model_router_base_url
        )
        client.set_strategy("api")  # Set default strategy

        message_broker_client: Final[MessageBrokerClient] = init_message_broker(
            config.message_broker_host,
            config.message_broker_port,
            logger,
        )
    except Exception as e:
        logger.error(f"Initialization failed: {e}", exc_info=True)
        sys.exit(1)

    # --- Start CPG Consumer Task ---
    logger.info(
        f"Starting CPG scan result consumer for topic: {config.cpg_scan_result_input_topic}"
    )
    consumer_task = asyncio.create_task(cpg_scan_result_consumer())
    try:
        # subscribe to topic
        message_broker_client.consume(
            config.cpg_scan_result_input_topic, on_consume_cpg_scan_result
        )
        logger.info(f"Subscribed to topic: {config.cpg_scan_result_input_topic}")
    except Exception as e:
        logger.error(
            f"Failed to subscribe to topic {config.cpg_scan_result_input_topic}: {e}",
            exc_info=True,
        )
        consumer_task.cancel()  # Stop the consumer if subscription fails
        sys.exit(1)

    # --- Define File Processing Logic ---
    async def process_file(
        filename: str,
        config: LLMDispatchSvcConfig,
        client: LLMClient,
        message_broker_client: MessageBrokerClient,
    ):
        logger.info(f"Processing file: {filename}")
        input_c_program_full_path = os.path.join(
            config.input_codebase_full_path, filename
        )

        # --- Get CPG Context ---
        # Derive executable name (assuming it's filename without .c)
        executable_name = filename.removesuffix(".c")
        cpg_context: Optional[CpgScanResult] = (
            executable_name_to_cpg_scan_result_map.get(executable_name)
        )

        if cpg_context:
            logger.info(f"Found CPG context for {executable_name}")
        else:
            # Decide behavior: skip processing, process without context, or wait?
            # Current implementation proceeds without context.
            logger.warning(
                f"No CPG context found for {executable_name} in map. Proceeding without context."
            )
            # You might want to add a check here to only proceed if context is required/available

        # --- Generate Prompt ---
        try:
            prompt: str = await full_prompt(
                config.system_prompt_full_path,
                config.user_prompt_full_path,
                input_c_program_full_path,
                cpg_context,  # Pass the retrieved context (or None)
            )
        except Exception as e:
            logger.error(
                f"Failed to create full prompt for {filename}: {e}", exc_info=True
            )
            return  # Skip processing this file

        if not prompt:
            logger.error(
                f"Generated prompt is empty for {filename}. Skipping LLM generation."
            )
            return

        # --- Generate Responses from LLMs ---
        try:
            logger.info(f"Generating responses for {filename} using {len(client.active_strategy.llms)} LLMs...")  # type: ignore
            responses = await client.generate(prompt)
            logger.info(f"Received {len(responses)} raw responses for {filename}.")
        except Exception as e:
            logger.error(
                f"Failed to generate responses for {filename}: {e}", exc_info=True
            )
            return  # Skip processing this file

        # --- Create Patch Responses ---
        if not responses:
            logger.warning(
                f"No responses generated for {filename}. Skipping output production."
            )
            return

        try:
            # Pass the single filename/id corresponding to these responses
            patch_responses: List[PatchResponse] = await create_patch_responses(
                responses, filename  # Pass filename as the identifier
            )
            logger.info(
                f"Created {len(patch_responses)} PatchResponse objects for {filename}."
            )
        except Exception as e:
            logger.error(
                f"Failed to create patch responses for {filename}: {e}", exc_info=True
            )
            return  # Skip processing this file

        # --- Produce Output ---
        if not patch_responses:
            logger.warning(
                f"No valid patch responses created for {filename}. Skipping output production."
            )
            return

        try:
            output_topic = config.message_broker_topics.get("response")
            if not output_topic:
                logger.error("Response topic not configured in message_broker_topics.")
                return
            await produce_output(
                output_topic,
                patch_responses,
                message_broker_client,
            )
            logger.info(f"Output produced for {filename} to topic {output_topic}.")
        except Exception as e:
            logger.error(f"Failed to produce output for {filename}: {e}", exc_info=True)
            # Continue to next file

    # --- Process Files ---
    filenames: List[str] = []
    if not os.path.isdir(config.input_codebase_full_path):
        logger.error(
            f"Input codebase path is not a valid directory: {config.input_codebase_full_path}"
        )
        # Clean up before exiting
        consumer_task.cancel()
        await asyncio.sleep(1)  # Allow cancellation to process
        sys.exit(1)

    _dir_contents = os.listdir(config.input_codebase_full_path)
    _wait_time = len(_dir_contents) * 30
    if _wait_time < 300:
        _wait_time = 300

    # Allow some time for connections and potential initial messages
    logger.info(
        f"Allowing {str(_wait_time)}s for code property graph generation and message consumption..."
    )
    await asyncio.sleep(_wait_time)
    logger.info("Initial wait complete. Proceeding with file processing.")

    for item in _dir_contents:
        item_path = os.path.join(config.input_codebase_full_path, item)
        if item.endswith(".c") and os.path.isfile(item_path):
            filenames.append(item)
        elif os.path.isdir(item_path):
            # Log skipping directories specifically
            logger.info(
                f"{config.appName} processes only .c files directly in the input path. Skipping directory: {item}"
            )
        else:
            # Log skipping other file types
            logger.info(f"Skipping non-.c file: {item}")

    if not filenames:
        logger.warning(
            f"No .c files found in {config.input_codebase_full_path}. Nothing to process."
        )
    else:
        logger.info(f"Found {len(filenames)} .c files to process: {filenames}")
        # Create tasks for processing each file
        tasks = [
            process_file(filename, config, client, message_broker_client)
            for filename in filenames
        ]
        # Run tasks concurrently
        await asyncio.gather(*tasks)
        logger.info("Finished processing all found .c files.")

    # --- Keep Running (Event-Driven Part) ---
    # The current file processing logic runs once at startup.
    # To make it truly event-driven based on CPG results, the logic inside `process_file`
    # would need to be triggered *by* the `cpg_scan_result_consumer` after a result is processed,
    # potentially using the `executable_name` to find the corresponding source file.
    # The current structure processes all files found initially and uses CPG results if available at that time.

    logger.info(
        "Initial file processing complete. Service running, waiting for new CPG scan results..."
    )
    # Keep the program running to allow the consumer task to continue receiving messages.
    # Wait for the consumer task to finish (which it won't unless cancelled or an error occurs)
    try:
        await consumer_task  # Keep running until consumer stops or is cancelled
    except asyncio.CancelledError:
        logger.info("Consumer task cancelled.")
    except Exception as e:
        logger.error(f"Consumer task exited with error: {e}", exc_info=True)

    logger.info("Shutting down.")
    # Add any cleanup needed here (e.g., disconnect message broker)


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("Interrupted by user. Exiting.")
    except Exception as e:
        # Catch top-level exceptions during startup/shutdown
        logging.error(f"Unhandled exception in main execution: {e}", exc_info=True)
        sys.exit(1)
