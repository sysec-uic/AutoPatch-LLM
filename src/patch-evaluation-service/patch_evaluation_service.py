import asyncio
import base64
import json
import logging
import os
import subprocess
import sys
import tempfile
from typing import Dict, Final, Tuple

from autopatchdatatypes import CrashDetail, PatchResponse, TransformerMetadata
from autopatchpubsub import MessageBrokerClient
from autopatchshared import (
    get_current_timestamp,
    init_logging,
    load_config_as_json,
    make_compile,
)
from patch_eval_config import PatchEvalConfig

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_PATCH_EVAL_SVC_CONFIG: Final[str] = "PATCH_EVAL_SVC_CONFIG"

# before configuration is loaded, use the default logger
logger = logging.getLogger(__name__)

# Global variables for the async queue and event loop.
async_crash_details_queue = asyncio.Queue()
async_patch_response_queue = asyncio.Queue()
event_loop: asyncio.AbstractEventLoop  # This will be set in main().


executables_to_process: set[str]
config: PatchEvalConfig
results: Dict[str, Dict[str, int]]

# Dictionary to store locks per CSV file
file_locks: Dict[str, asyncio.Lock] = {}


async def run_file_async(
    executable_path: str,
    executable_name: str,
    crash_detail: CrashDetail,
    temp_crash_file_full_path: str,
    timeout: int = 10,
) -> int:
    """
    Asynchronously run the binary at executable_path with input from CrashDetail.
    """
    crash_bytes = base64.b64decode(crash_detail.base64_message)
    crash = crash_bytes.decode("utf-8", errors="replace")
    proc = None  # Initialize proc for cleanup in case of timeout

    try:
        if crash_detail.is_input_from_file:
            proc = await asyncio.create_subprocess_exec(
                executable_path,
                temp_crash_file_full_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(),
                timeout=timeout,
            )
        else:
            proc = await asyncio.create_subprocess_exec(
                executable_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(input=crash_bytes),
                timeout=timeout,
            )

        logger.debug(f"stdout: {stdout.decode()}")
        logger.debug(f"stderr: {stderr.decode()}")
        logger.info(f"stdout: {stdout.decode()}")
        logger.info(f"stderr: {stderr.decode()}")

    except asyncio.TimeoutError:
        if proc:
            proc.kill()
            await proc.communicate()
        logger.error(f"Timeout after {timeout} seconds running {executable_name}")
        return -1

    except Exception as e:
        logger.error(f"Exception during runtime: {e}")
        return -1

    # Process return code handling:
    if proc.returncode == 0:
        logger.debug(f"File {executable_name} ran with input {crash} without errors.")
        return 0
    elif proc.returncode == 1:
        logger.info(f"Run of {executable_name} terminated with return code 1.")
        return 1
    elif proc.returncode is None:
        logger.error("Process did not return an exit code; treating as error.")
        return -1
    else:
        signal_code = proc.returncode - 128
        logger.info(f"Run of {executable_name} terminated with signal {signal_code}.")
        return signal_code


# TODO extract this into autopatchshared
def compile_file(
    file_path: str,
    file_name: str,
    executable_path: str,
    compiler_tool_full_patch: str,
    compiler_warning_flags: str,
    compiler_feature_flags: str,
    compiler_timeout: int,
) -> str:
    """
    Compiles the file at file_path into a binary executable in the executable_path directory.
    """
    # form the command
    executable_name = file_name.split(".")[0]
    executable_full_path = os.path.join(executable_path, executable_name)
    command = f"{compiler_tool_full_patch} {file_path} {compiler_warning_flags} {compiler_feature_flags} {executable_full_path}"

    # run the command
    try:
        result = subprocess.run(
            [command],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=compiler_timeout,
            shell=True,
        )
        logger.debug(f"Compiled with command {command}")
        logger.debug(f"stderr of the compile: {result.stderr}")
    except Exception as e:
        # if an error occurs during compilation, log
        logger.error(f"An error occurred while compiling {file_path}: {e}")
        logger.error(f"stderr of the compile: {result.stderr}")
    finally:
        # log the command and return either the path to the executable or an empty string on failure
        if os.path.exists(executable_full_path):
            logger.info(f"Executable {executable_full_path} exists.")
            return executable_name
        else:
            logger.error(f"Failed to compile {file_path}")
            return ""


def write_crashes_csv(
    crash_detail: CrashDetail,
    return_code: int,
    csv_path: str,
) -> None:
    """
    Process crash by logging in the associated executable's csv file.

    Each line contains the timestamp, crash detail, return code, and inputFromFile.
    """

    # Ensure the output directory exists.
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    # Check if the file exists and is not empty.
    write_header = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0

    with open(csv_path, "a", encoding="utf-8") as f:
        if write_header:
            f.write("timestamp,crash_detail,return_code,inputFromFile\n")

        logger.info(f"  - {crash_detail}")
        timestamp = get_current_timestamp()

        line = f"{timestamp},{crash_detail.base64_message},{return_code},{crash_detail.is_input_from_file}\n"
        f.write(line)


# TODO add MQTT publish
async def log_crash_information(
    results_path: str, executable_name: str, crash_detail: CrashDetail, return_code: int
) -> None:
    """
    invokes the call to log the crash information for the given executable
    ensuring that only one coroutine writes to the CSV at a time
    """
    logger.info(f"Updating the results csv for {crash_detail.executable_name}")
    csv_path: Final[str] = os.path.join(results_path, f"{executable_name}.csv")

    if csv_path not in file_locks:
        file_locks[csv_path] = asyncio.Lock()

    async with file_locks[csv_path]:
        await asyncio.to_thread(write_crashes_csv, crash_detail, return_code, csv_path)


# TODO This assumes the batch run is complete, update to run after each eval and not assume a batch is complete
def log_results(results: dict, results_path: str) -> None:
    """
    logs the results of the entire run (all files tested) in a human-readable markdown file and a csv file describing
    the results
    """
    # create the paths
    log_path = os.path.join(results_path, "evaluation.md")
    csv_log_path = os.path.join(results_path, "evaluation.csv")
    # tallies for total and addressed crashes
    total_crashes = 0
    total_patched_crashes = 0

    logger.info(f"Creating batched info file {log_path}.")
    logger.info(f"Creating batched csv file {csv_log_path}.")

    with open(log_path, "w") as log:
        with open(csv_log_path, "w") as csv_log:
            # write the headers for both files
            log.write("# Results of running patches:\n")
            csv_log.write(
                "executable_name,triggers_addressed,triggers_total,success_rate,designation[S,P,F]\n"
            )
            # iterate through the evaluated code
            for executable_name in results.keys():
                total = results[executable_name]["total_crashes"]
                # if the total number of crashes is 0, then no crashes were associated with this executable, skip
                if total == 0:
                    continue

                # get the number of patched crashes, the success rate, and calculate its designation
                patched = results[executable_name]["patched_crashes"]
                success_rate = round(patched / total * 100, 2)
                designation = ""
                designation_shorthand = ""
                if success_rate == 100:
                    designation = "potential patch success."
                    designation_shorthand = "S"
                elif success_rate >= 80:
                    designation = "partial potential patch success."
                    designation_shorthand = "P"
                else:
                    designation = "patch failure."
                    designation_shorthand = "F"

                # write the results in markdown
                line = f"### {executable_name}\n"
                line += f"**Patch addresses {patched} out of {total} trigger conditions.**\n\n"
                line += f"**Patch is {success_rate}% successful: {designation}**\n\n"
                log.write(line)

                # add the csv line
                csv_log.write(
                    f"{executable_name},{patched},{total},{success_rate},{designation_shorthand}\n"
                )
                # update the tallies
                total_crashes += total
                total_patched_crashes += patched

            if total_crashes == 0:
                # none of the crashes were associated with any of the executables
                # or the results dict was empty
                return
            # get the total success rate, log in markdown file
            total_success_rate = round(total_patched_crashes / total_crashes * 100, 2)
            line = f"\n ### Total success rate of {len(results.keys())} files is {total_patched_crashes} / {total_crashes}, or {total_success_rate}%.\n"
            log.write(line)
            logger.info(f"Success of evaluation: {total_success_rate}%.")


async def map_cloud_event_as_patch_response(
    patch_response_cloud_event_str: str,
) -> PatchResponse:
    """
    Maps a CloudEvent JSON string to a PatchResponse object.

    Parameters:
        cloud_event (str): The CloudEvent JSON string.

    Returns:
        PatchResponse: The mapped patch response.
    """
    cloud_event: Dict = json.loads(patch_response_cloud_event_str)

    data = cloud_event.get("data", {})

    _transformer_metadata = data.get("TransformerMetadata", {})

    return PatchResponse(
        executable_name=data.get("executable_name", ""),
        patch_snippet_base64=data.get("patch_snippet_base64", ""),
        TransformerMetadata=TransformerMetadata(
            llm_name=_transformer_metadata.get("llm_name", ""),
            llm_flavor=_transformer_metadata.get("llm_flavor", ""),
            llm_version=_transformer_metadata.get("llm_version", ""),
        ),
        status=data.get("status", ""),
    )


async def process_patch_response(patch_response_str: str):
    """Asynchronously process an item."""
    patch_response: PatchResponse = await map_cloud_event_as_patch_response(
        patch_response_str
    )
    logger.info(f"Not implemented yet: process_patch_response {patch_response}")
    # await process_patch_response(patch_response)


async def map_cloud_event_as_crash_detail(
    crash_detail_cloud_event_str: str,
) -> CrashDetail:
    """
    Maps a CloudEvent JSON string to a CrashDetail object.

    Parameters:
        cloud_event (str): The CloudEvent JSON string.

    Returns:
        CrashDetail: The mapped crash detail.
    """
    cloud_event: Dict = json.loads(crash_detail_cloud_event_str)

    data = cloud_event.get("data", {})

    return CrashDetail(
        executable_name=data.get("executable_name", ""),
        base64_message=data.get("crash_detail_base64", ""),
        is_input_from_file=data.get("is_input_from_file", False),
    )


def load_config(
    patch_eval_svc_config_full_path: str, logger: logging.Logger
) -> PatchEvalConfig:
    """
    Load the configuration for the patch evaluation service.
    """
    _config = load_config_as_json(patch_eval_svc_config_full_path, logger)
    return PatchEvalConfig(**_config)


def on_consume_patch_response(patch_response_str: str) -> None:
    """
    This is synchronous function that’s called from non‑async code.
    It uses the globally stored event_loop to schedule a call to
    async_queue.put_nowait in a thread‑safe manner.
    """
    logger.info(f"in on_consume_patch_response received {patch_response_str}")
    # Schedule adding the event to the async queue.
    # Use call_soon_threadsafe so that this function can be safely called
    # from threads outside the event loop.
    global event_loop
    event_loop.call_soon_threadsafe(
        async_patch_response_queue.put_nowait, patch_response_str
    )


def on_consume_crash_detail(cloud_event_str: str) -> None:
    """
    This is synchronous function that’s called from non‑async code.
    It uses the globally stored event_loop to schedule a call to
    async_queue.put_nowait in a thread‑safe manner.
    """
    logger.info(f"in on_consume_crash_detail received {cloud_event_str}")
    # Schedule adding the event to the async queue.
    # Use call_soon_threadsafe so that this function can be safely called
    # from threads outside the event loop.
    global event_loop
    event_loop.call_soon_threadsafe(
        async_crash_details_queue.put_nowait, cloud_event_str
    )


def prep_executables_for_evaluation(
    executables_full_path: str,
    patched_codes_directory_path: str,
    compiler_tool_full_path: str,
    compiler_warning_flags: str,
    compiler_feature_flags: str,
    compile_timeout: int,
) -> Tuple[set[str], Dict[str, Dict[str, int]]]:
    # list of files successfully compiled and a dict for the results of each
    executables = set()
    results: Dict[str, Dict[str, int]] = dict()
    # iterate through the patched codes directory
    # this will be replaced with a message broker subscription
    for file_name in os.listdir(patched_codes_directory_path):
        fully_qualified_file_path = os.path.join(
            patched_codes_directory_path, file_name
        )
        if os.path.isdir(fully_qualified_file_path):
            logger.info(
                "Patch Evaluation Service does not yet support complex project directories."
            )
            logger.info(f"Skipping directory: {fully_qualified_file_path}")
            continue
        # compile the file
        logger.info(f"Compiling: {fully_qualified_file_path}")
        executable_name = compile_file(
            fully_qualified_file_path,
            file_name,
            executables_full_path,
            compiler_tool_full_path,
            compiler_warning_flags,
            compiler_feature_flags,
            compile_timeout,
        )
        # if the compilation was successful, then add the executable path to the list of executables to run
        if executable_name != "":
            executables.add(executable_name)
            results[executable_name] = dict()
            results[executable_name]["total_crashes"] = 0
            results[executable_name]["patched_crashes"] = 0
    return (executables, results)


async def process_item(item):
    """Asynchronously process an item."""
    crash_detail = await map_cloud_event_as_crash_detail(item)
    await process_crash_detail(crash_detail)


async def process_crash_detail(crash_detail: CrashDetail) -> None:
    logger.info(f"Processing crash {crash_detail}")
    # TODO evaluate if we can remove this check
    # if the crash executable is not in our executables base, then skip it
    if crash_detail.executable_name not in executables_to_process:
        logger.info(
            f"{crash_detail.executable_name} not in set of compiled executables to process..skipping"
        )
        return

    if crash_detail.is_input_from_file:
        temp_crash_file = tempfile.NamedTemporaryFile()
        logger.info("temp_crash_file name: " + temp_crash_file.name)
        temp_crash_file.write(base64.b64decode(crash_detail.base64_message))

    # run the file
    executable_path = os.path.join(
        config.executables_full_path, crash_detail.executable_name
    )
    return_code = await run_file_async(
        executable_path,
        crash_detail.executable_name,
        crash_detail,
        "" if not crash_detail.is_input_from_file else temp_crash_file.name,
        config.run_timeout,
    )

    # log the crash information to that executables dedicated csv file
    logger.info(
        f"Result of running file {crash_detail.executable_name}: {return_code}."
    )
    await log_crash_information(
        config.patch_eval_results_full_path,
        crash_detail.executable_name,
        crash_detail,
        return_code,
    )

    # update the results dict for that executable with the result of the run
    results[crash_detail.executable_name]["total_crashes"] += 1
    if return_code == 0 or return_code == 1:
        results[crash_detail.executable_name]["patched_crashes"] += 1
    # log the batched results
    # log_results(results, config.patch_eval_results_full_path)
    logger.info("Simulating logging the batched results")
    logger.info("Results: " + str(results))


async def patch_response_consumer():
    """Continuously consume items from the async queue."""
    """
        this consumer coroutine waits for items from the asyncio.Queue
        and processes each with process_item(). This runs continuously in the event loop.
    """
    while True:
        item = await async_patch_response_queue.get()
        try:
            await process_patch_response(item)
        finally:
            async_patch_response_queue.task_done()


async def crash_detail_consumer():
    """Continuously consume items from the async queue."""
    """
        this consumer coroutine waits for items from the asyncio.Queue
        and processes each with process_item(). This runs continuously in the event loop.
    """
    while True:
        item = await async_crash_details_queue.get()
        try:
            await process_item(item)
        finally:
            async_crash_details_queue.task_done()


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
    global event_loop
    global logger
    global executables_to_process
    global config
    global results

    # initialize the configmap
    config_file_full_path = os.environ.get(CONST_PATCH_EVAL_SVC_CONFIG)
    if config_file_full_path is None:
        logger.error(
            f"Environment variable {CONST_PATCH_EVAL_SVC_CONFIG} is not set. Exiting."
        )
        sys.exit(1)
    config = load_config(config_file_full_path, logger)

    # initialize the logger using injected configuration
    logger = init_logging(config.logging_config, config.appname)

    # get the current ISO timestamp
    # EVAL_SVC_START_TIMESTAMP: Final[str] = get_current_timestamp()

    # log some info, make the directories if they DNE
    logger.info("AppVersion: " + config.version)
    logger.info("Creating executables directory: " + config.executables_full_path)

    # list of files successfully compiled and a dict for the results of each
    executables_to_process, results = prep_executables_for_evaluation(
        config.executables_full_path,
        config.patched_codes_path,
        config.compiler_tool_full_path,
        config.compiler_warning_flags,
        config.compiler_feature_flags,
        config.compile_timeout,
    )

    event_loop = asyncio.get_running_loop()

    # Start the consumer coroutine as a background task.
    asyncio.create_task(crash_detail_consumer())
    asyncio.create_task(patch_response_consumer())

    message_broker_client: Final[MessageBrokerClient] = init_message_broker(
        config.message_broker_host,
        config.message_broker_port,
        logger,
    )

    # subscribe to topic
    message_broker_client.consume(
        config.autopatch_patch_response_input_topic, on_consume_patch_response
    )
    message_broker_client.consume(
        config.autopatch_crash_detail_input_topic, on_consume_crash_detail
    )

    # Keep the program running indefinitely, waiting for more events.
    await asyncio.Future()  # This future will never complete.


if __name__ == "__main__":
    # Run the event loop
    asyncio.run(main())
