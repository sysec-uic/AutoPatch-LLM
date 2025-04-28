import asyncio
import base64
import json
import logging
import os
import subprocess
import sys
import tempfile
import time
from typing import Dict, Final, Set, Tuple

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
async_crash_details_cloud_events_queue = asyncio.Queue()
async_patch_response_cloud_events_queue = asyncio.Queue()

async_crash_details_ready_queue = asyncio.Queue()
async_patch_response_ready_queue = asyncio.Queue()

event_loop: asyncio.AbstractEventLoop  # This will be set in main().

crashdetails_map: Dict[str, CrashDetail] = {}  # uid → crash detail
patchresponses_map: Dict[str, Dict[str, PatchResponse]] = {}  # uid → llm_name → patch

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
    if not executable_path:
        return -1

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
    source_file_full_path: str,
    output_dir_path: str,
    compiler_tool_full_patch: str,
    compiler_warning_flags: str,
    compiler_feature_flags: str,
    compiler_timeout: int,
) -> str:
    """
    Compiles the file at file_path into a binary executable in the executable_path directory.
    """
    # form the command
    executable_name = os.path.basename(source_file_full_path).split(".")[0]
    executable_full_path = os.path.join(output_dir_path, executable_name)
    command = f"{compiler_tool_full_patch} {source_file_full_path} {compiler_warning_flags} {compiler_feature_flags} {executable_full_path}"

    result = None  # Ensure it's defined in scope

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
        logger.error(f"An error occurred while compiling {source_file_full_path}: {e}")
        if result:
            logger.error(f"stderr of the compile: {result.stderr}")
    finally:
        if os.path.exists(executable_full_path):
            logger.info(f"Executable {executable_full_path} exists.")
            return executable_full_path
        logger.error(f"Failed to compile {source_file_full_path}")
        return ""


# TODO convert to pandas
def write_crashes_csv(
    crash_detail: CrashDetail,
    patch_base64_str: str,
    return_code: int,
    csv_path: str,
    llm_name: str,
    llm_flavor: str,
    llm_version: str,
) -> None:
    """
    Write crash details and LLM information to a CSV file.
    This function appends a record containing crash details and
    associated metadata to the CSV file specified by csv_path.
    If the CSV file does not exist or is empty, it first writes
    a header line before appending the new record.
    The record includes a timestamp, executable name, crash
    message (base64 encoded), return code, an indicator of whether
    the input was provided from a file, and details about the LLM
    used (name, flavor, version) along with a base64 encoded patch string.
    Args:
        crash_detail (CrashDetail):
            - executable_name: Name of the crashing executable.
            - base64_message: The crash message encoded in base64.
            - is_input_from_file: A bool indicating if the input was provided from a file.
        patch_base64_str (str): The base64 encoded patch string applied.
        return_code (int): The return code resulting from the crash.
        csv_path (str): The file path to the CSV where the record should be written.
        llm_name (str): The name of the large language model (LLM) used.
        llm_flavor (str): The variant or flavor of the LLM.
        llm_version (str): The version of the LLM.
    Returns:
        None
    """

    # Ensure the output directory exists.
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    # Check if the file exists and is not empty.
    write_header = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0

    with open(csv_path, "a", encoding="utf-8") as f:
        if write_header:
            logger.info("Writing header to CSV file.")
            header: Final[str] = (
                "timestamp,"
                "program_name,"
                "crash_detail,"
                "return_code,"
                "isInputFromFile,"
                "llm_name,"
                "llm_flavor,"
                "llm_version,"
                "patch_base64_str\n"
            )
            f.write(header)

        line: Final[str] = (
            f"{get_current_timestamp()},"
            f"{crash_detail.executable_name},"
            f"{crash_detail.base64_message},"
            f"{return_code},"
            f"{crash_detail.is_input_from_file},"
            f"{llm_name},"
            f"{llm_flavor},"
            f"{llm_version}"
            f"{patch_base64_str}\n"
        )
        f.write(line)


# TODO add MQTT publish
async def log_crash_information(
    results_path: str,
    executable_name: str,
    crash_detail: CrashDetail,
    patch_base64_str: str,
    return_code: int,
    llm_name: str,
    llm_flavor: str,
    llm_version: str,
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
        await asyncio.to_thread(
            write_crashes_csv,
            crash_detail,
            patch_base64_str,
            return_code,
            csv_path,
            llm_name,
            llm_flavor,
            llm_version,
        )


# TODO This assumes the batch run is complete,
# update to run after each eval and not assume a batch is complete
def log_results(results: dict, results_path: str) -> None:
    """
    logs the results of the entire run (all files tested)
    in a human-readable markdown file and a csv file describing
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

    with open(log_path, "w") as md_results_doc:
        with open(csv_log_path, "w") as csv_output_file:
            # write the headers for both files
            md_results_doc.write("# Results of running patches:\n")
            csv_output_file.write(
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
                md_results_doc.write(line)

                # add the csv line
                csv_output_file.write(
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
            line = (
                f"\n ### Total success rate of {len(results.keys())} files is "
                f"{total_patched_crashes} / {total_crashes}, "
                f"or {total_success_rate}%.\n"
            )
            md_results_doc.write(line)
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


async def handle_ready(
    uid: str, crash_detail: CrashDetail, patch_response: PatchResponse
) -> None:
    # There is where we will move the run file and evaluation logic to
    # we will need to apply a patch to a C source file and then compile it
    # the original C source file will be in the assets input_codebase directory
    # the patch will come from the patch_response
    # finally we update the results dict with the results of the run

    logger.info(f"[READY] {uid} → crash: {crash_detail}, patch: {patch_response}")
    if patch_response.status == "fail":
        logger.info(f"Patch response for {uid} is empty, skipping.")
        return

    if uid not in executables_to_process:
        logger.info(f"{uid} not in set of programs to evaluate..skipping")
        return

    if crash_detail.is_input_from_file:
        temp_crash_file = tempfile.NamedTemporaryFile()
        logger.debug(f"temp_crash_file name: {temp_crash_file.name}")
        temp_crash_file.write(base64.b64decode(crash_detail.base64_message))

    patch_file_as_str = base64.b64decode(patch_response.patch_snippet_base64).decode(
        "utf-8"
    )
    logger.info(f"patch preview: {patch_file_as_str}")

    patched_filename = os.path.join(
        config.executables_full_path, "tmp", patch_response.executable_name + ".c"
    )

    # todo delete this file after the run
    with open(patched_filename, "w") as f:
        f.write(patch_file_as_str)

    # compile the patched source code
    executable_full_path = compile_file(
        # temp_patched_source_code_file.name,
        patched_filename,
        config.executables_full_path,
        config.compiler_tool_full_path,
        config.compiler_warning_flags,
        config.compiler_feature_flags,
        config.compile_timeout,
    )

    return_code = await run_file_async(
        executable_full_path,
        uid,
        crash_detail,
        "" if not crash_detail.is_input_from_file else temp_crash_file.name,
        config.run_timeout,
    )

    # TODO add LLM context, rename to produce output
    # log the crash information to that executables dedicated csv file
    logger.info(f"Result of running file {uid}: {return_code}.")
    await log_crash_information(
        config.patch_eval_results_full_path,
        uid,
        crash_detail,
        patch_response.patch_snippet_base64,
        return_code,
        patch_response.TransformerMetadata.llm_name,
        patch_response.TransformerMetadata.llm_flavor,
        patch_response.TransformerMetadata.llm_version,
    )

    # update the results dict for that executable with the result of the run
    results[uid + ".c"]["total_crashes"] += 1
    if return_code == 0 or return_code == 1:
        results[uid + ".c"]["patched_crashes"] += 1
    # log the batched results
    # log_results(results, config.patch_eval_results_full_path)
    logger.info("Simulating logging the batched results")
    logger.info("Results: " + str(results))


async def map_updater(timeout_seconds: int = 260):
    timed_out_uids: Set[str] = (
        set()
    )  # as we can have multiple LLMs creating patches for a uid
    processed_pairs: Set[Tuple[str, str]] = set()  # (uid, llm_name)
    pending_uids: Set[str] = set()
    seen_times: Dict[str, float] = {}  # uid → first seen timestamp (monotonic)

    while True:
        if not pending_uids:
            done, _ = await asyncio.wait(
                [
                    asyncio.create_task(async_crash_details_ready_queue.get()),
                    asyncio.create_task(async_patch_response_ready_queue.get()),
                ],
                return_when=asyncio.FIRST_COMPLETED,
            )

            for task in done:
                uid = task.result()
                logger.info(f"[map_updater] Received UID: {uid}")
                if uid in timed_out_uids:
                    logger.info(f"[map_updater] UID {uid} timed out, skipping.")
                    continue
                pending_uids.add(uid)
                if uid not in seen_times:
                    seen_times[uid] = time.monotonic()

        now = time.monotonic()

        # copy to avoid modifying set during iteration
        for uid in list(pending_uids):
            age = now - seen_times.get(uid, now)
            if age > timeout_seconds:
                logger.warning(
                    f"[map_updater] Timeout expired for UID={uid} (age={age:.2f}s), dropping it."
                )
                pending_uids.remove(uid)
                seen_times.pop(uid, None)
                timed_out_uids.add(uid)  # Mark it as timed out
                continue

            crash_ready = uid in crashdetails_map
            patch_ready = uid in patchresponses_map
            logger.info(
                f"[map_updater] UID={uid} | crash_ready={crash_ready}, patch_ready={patch_ready}, age={age:.1f}s"
            )
            if not (crash_ready and patch_ready):
                continue

            # patches come in much faster than crash responses
            # so at this time we don't need special handling
            # for re-queueing crash details
            for llm_name, patch in patchresponses_map[uid].items():
                key = (uid, llm_name)
                if key not in processed_pairs:
                    logger.info(
                        f"[map_updater] Processing (uid={uid}, llm_name={llm_name})"
                    )
                    await handle_ready(uid, crashdetails_map[uid], patch)
                    processed_pairs.add(key)

            pending_uids.remove(uid)
            seen_times.pop(uid, None)

        # Give other tasks a chance, and retry any incomplete UIDs
        await asyncio.sleep(10.0)


async def patch_response_ready_producer(patch_response_str: str):
    """Asynchronously process an item."""
    patch_response: PatchResponse = await map_cloud_event_as_patch_response(
        patch_response_str
    )
    logger.info(f"Adding {patch_response.executable_name} to patchresponses_map")
    if patch_response.executable_name not in patchresponses_map:
        patchresponses_map[patch_response.executable_name] = {}
    patchresponses_map[patch_response.executable_name][
        patch_response.TransformerMetadata.llm_name
    ] = patch_response

    event_loop.call_soon_threadsafe(
        async_patch_response_ready_queue.put_nowait,
        patch_response.executable_name,
    )


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


def on_consume_patch_response(patch_response_as_cloud_event_str: str) -> None:
    """
    This is synchronous function that’s called from non‑async code.
    It uses the globally stored event_loop to schedule a call to
    async_queue.put_nowait in a thread‑safe manner.
    """
    logger.info("Received patch response from message broker.")
    logger.debug(f"Received patch response: {patch_response_as_cloud_event_str}")
    # Schedule adding the event to the async queue.
    # Use call_soon_threadsafe so that this function can be safely called
    # from threads outside the event loop.
    event_loop.call_soon_threadsafe(
        async_patch_response_cloud_events_queue.put_nowait,
        patch_response_as_cloud_event_str,
    )


def on_consume_crash_detail(crash_detail_as_cloud_event_str: str) -> None:
    """
    This is synchronous function that’s called from non‑async code.
    It uses the globally stored event_loop to schedule a call to
    async_queue.put_nowait in a thread‑safe manner.
    """
    logger.info("Received crash detail from message broker.")
    logger.debug(f"Received crash detail: {crash_detail_as_cloud_event_str}")
    # Schedule adding the event to the async queue.
    # Use call_soon_threadsafe so that this function can be safely called
    # from threads outside the event loop.
    event_loop.call_soon_threadsafe(
        async_crash_details_cloud_events_queue.put_nowait,
        crash_detail_as_cloud_event_str,
    )

async def prep_programs_for_evaluation(
    executables_full_path: str,
    patched_codes_directory_path: str,
    compiler_tool_full_path: str,
    compiler_warning_flags: str,
    compiler_feature_flags: str,
    compile_timeout: int,
    make_tool_full_path: str,

) -> Tuple[set[str], Dict[str, Dict[str, int]]]:

    # list of files to consider for evaluation and a dict for the results of each
    executables = set()
    results: Dict[str, Dict[str, int]] = dict()
    executable_name = ""
    # iterate through the patched codes directory
    for file_name in os.listdir(patched_codes_directory_path):
        fully_qualified_file_path = os.path.join(
            patched_codes_directory_path, file_name
        )
        # if the file is a directory

        if os.path.isdir(fully_qualified_file_path):
            logger.info(f"Compiling project directory: {fully_qualified_file_path}")

            output_executable_fully_qualified_path = os.path.join(
                executables_full_path, file_name
            )

            # compile using shared make_compile
            compiled = make_compile(
                fully_qualified_file_path,
                output_executable_fully_qualified_path,
                compiler_tool_full_path,
                make_tool_full_path,
                logger,
            )
            # log errors and continue
            if not compiled:
                logger.error(
                    f"Make compilation of project directory {fully_qualified_file_path} failed."
                )
                continue
            executable_name = file_name
        else:
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


async def process_crash_detail_item(item):
    """Asynchronously process an item."""
    crash_detail = await map_cloud_event_as_crash_detail(item)
    await crash_detail_ready_producer(crash_detail)


async def crash_detail_ready_producer(
    crash_detail: CrashDetail,
) -> None:
    logger.info(f"Adding {crash_detail.executable_name} to crashdetails_map")
    crashdetails_map[crash_detail.executable_name] = crash_detail
    event_loop.call_soon_threadsafe(
        async_crash_details_ready_queue.put_nowait,
        crash_detail.executable_name,
    )


async def patch_response_consumer():
    """Continuously consume items from the async queue."""
    """
        this consumer coroutine waits for items from the asyncio.Queue
        and processes each with process_item(). This runs continuously in the event loop.
    """
    while True:
        item = await async_patch_response_cloud_events_queue.get()
        try:
            await patch_response_ready_producer(item)
        finally:
            async_patch_response_cloud_events_queue.task_done()


async def crash_detail_consumer():
    """Continuously consume items from the async queue."""
    """
        this consumer coroutine waits for items from the asyncio.Queue
        and processes each with process_item(). This runs continuously in the event loop.
    """
    while True:
        item = await async_crash_details_cloud_events_queue.get()
        try:
            await process_crash_detail_item(item)
        finally:
            async_crash_details_cloud_events_queue.task_done()


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

    # log some info, make the directories if they DNE
    logger.info("AppName: " + config.appname)
    logger.info("AppVersion: " + config.version)


    # create task for prepping patched codes for eval

    task = asyncio.create_task(
        prep_programs_for_evaluation(
            config.executables_full_path,
            config.patched_codes_path,
            config.compiler_tool_full_path,
            config.compiler_warning_flags,
            config.compiler_feature_flags,
            config.compile_timeout,
            config.make_tool_full_path,
        )
    )

    event_loop = asyncio.get_running_loop()

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

    executables_to_process, results = await task

    await asyncio.gather(
        crash_detail_consumer(),
        patch_response_consumer(),
        map_updater(),
    )


if __name__ == "__main__":
    # Run the event loop
    asyncio.run(main())
