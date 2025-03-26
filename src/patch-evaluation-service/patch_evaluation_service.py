import asyncio
import threading
import asyncio
import tempfile
import base64
import json
import logging
import logging.config
import os
import subprocess
import sys
from typing import Final, Tuple, Dict

from autopatchdatatypes import CrashDetail
from autopatchpubsub import MessageBrokerClient
from autopatchshared import init_logging, load_config_as_json, get_current_timestamp
from patch_eval_config import PatchEvalConfig

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_PATCH_EVAL_SVC_CONFIG: Final[str] = "PATCH_EVAL_SVC_CONFIG"

# before configuration is loaded, use the default logger
logger = logging.getLogger(__name__)

# Global variables for the async queue and event loop.
async_crash_details_queue = asyncio.Queue()
event_loop: asyncio.AbstractEventLoop  # This will be set in main().

executables_to_process: set[str]
config: PatchEvalConfig
results: Dict[str, Dict[str, int]]


def create_temp_crash_file(crash_detail: CrashDetail, temp_dir_path: str) -> str:
    """
    Creates a file with the crash_detail information for passing an executable a path via file.
    """
    os.makedirs(temp_dir_path, exist_ok=True)
    crash_path = os.path.join(temp_dir_path, "crash")

    with open(crash_path, "wb") as crash_file:
        crash_file.write(base64.b64decode(crash_detail.base64_message))
    return crash_path


def run_c_program(executable_path, input_data, file_input=False):
    """
    Invokes a C program located at `executable_path` with the provided input.

    Parameters:
        executable_path (str): The path to the C executable.
        input_data (str): The input data to be provided to the executable.
        file_input (bool): If True, writes the input_data to a temporary file and passes
                           the file path as an argument to the executable. If False,
                           the input_data is sent directly to the program's STDIN.

    Returns:
        tuple: A triplet (exit_code, stdout, stderr) where exit_code is an integer
               representing the program's exit status.
    """
    if file_input:
        # Write input_data to a temporary file.
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tmp_file:
            tmp_file.write(input_data)
            tmp_file.flush()
            tmp_filename = tmp_file.name

        try:
            # Run the executable with the temporary file as an argument.
            result = subprocess.run(
                [executable_path, tmp_filename],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,  # Ensures the output is returned as strings.
            )
        finally:
            # Clean up the temporary file.
            os.remove(tmp_filename)
    else:
        # Run the executable with input_data piped into STDIN.
        result = subprocess.run(
            [executable_path],
            input=input_data,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,  # Ensure input and outputs are handled as strings.
        )

    return result.returncode, result.stdout, result.stderr


# TODO to be replaced with def run_c_program
def run_file(
    executable_path: str,
    executable_name: str,
    crash_detail: CrashDetail,
    temp_crash_file: str,
    timeout: int = 10,
) -> int:
    """
    Run the binary at executable_path with the input given by CrashDetail, either through stdin or via a file.
    """

    # get the crash detail and form the command
    crash_bytes = base64.b64decode(crash_detail.base64_message)
    crash = crash_bytes.decode("utf-8", errors="replace")
    if crash_detail.is_input_from_file:
        command = f"{executable_path} {temp_crash_file}"
    else:
        command = f"echo {crash} | {executable_path}"

    # run the command
    try:
        result = subprocess.run(
            [command],
            check=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            shell=True,
        )
        # return 0 on complete success
        logger.debug(f"Command run: {command}")
        logger.debug(f"Command executed with result: {result}")
        logger.debug(
            f"File {executable_name} ran with input {crash} without any terminating errors."
        )
    # if the program terminated with a signal != 0
    except subprocess.CalledProcessError as e:
        logger.debug(f"Command run: {command}")
        logger.info(
            f"Run of {executable_name} terminated with return code {e.returncode}."
        )
        # if returncode == 1, then return it, otherwise subtract 128 to get the interrupting signal and return
        if e.returncode == 1:
            return 1
        return e.returncode - 128
    # if an exception occurred in running the process, this is an error.
    except Exception as e:
        logger.debug(f"Command run: {command}")
        logger.error(f"An exception occurred during runtime: {e}")
        return -1
    return 0


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


# NEEDS executable name for correlation? at present the csv title is the executable name
# TODO add MQTT publish and async
def log_crash_information(
    results_path: str, executable_name: str, crash_detail: CrashDetail, return_code: int
) -> None:
    """
    invokes the call to log the crash information for the given executable
    """
    csv_path: Final[str] = os.path.join(results_path, f"{executable_name}.csv")

    write_crashes_csv(crash_detail, return_code, csv_path)


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

            # if total crashes == 0, then none of the crashes were associated with any of the executables, or the results dict was empty, return
            if total_crashes == 0:
                return
            # get the total success rate, log in markdown file
            total_success_rate = round(total_patched_crashes / total_crashes * 100, 2)
            line = f"\n ### Total success rate of {len(results.keys())} files is {total_patched_crashes} / {total_crashes}, or {total_success_rate}%.\n"
            log.write(line)
            logger.info(f"Success of evaluation: {total_success_rate}%.")


def map_cloud_event_as_crash_detail(
    crash_detail_cloud_event_str: str,
) -> CrashDetail:
    """
    Maps a CloudEvent JSON string to a CrashDetail object.

    Parameters:
        cloud_event (str): The CloudEvent JSON string.

    Returns:
        CrashDetail: The mapped crash detail.
    """
    cloud_event: dict = json.loads(crash_detail_cloud_event_str)

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
    for file_name in os.listdir(patched_codes_directory_path):
        file_path = os.path.join(patched_codes_directory_path, file_name)
        # compile the file
        logger.info(f"Compiling: {file_path}")
        executable_name = compile_file(
            file_path,
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
    logger.info(f"Processing item: {item}")
    # Simulate asynchronous work (e.g., I/O).
    crash_detail = map_cloud_event_as_crash_detail(item)
    await process_crash_detail(crash_detail)
    logger.info(f"Done Processing item")
    # await asyncio.sleep(1)


async def process_crash_detail(crash_detail: CrashDetail) -> None:
    logger.info(f"Processing crash {crash_detail}")
    # TODO evaluate if we can remove this check
    # if the crash executable is not in our executables base, then skip it
    if crash_detail.executable_name not in executables_to_process:
        logger.info(
            f"{crash_detail.executable_name} not in set of compiled executables to process..skipping"
        )
        return

    # determine if we need to create a temporary crash file, make it if needed
    temp_crash_file: str = ""
    if crash_detail.is_input_from_file:
        temp_crash_file = create_temp_crash_file(
            crash_detail, config.temp_crashes_full_path
        )

    # run the file
    executable_path = os.path.join(
        config.executables_full_path, crash_detail.executable_name
    )
    return_code = run_file(
        executable_path,
        crash_detail.executable_name,
        crash_detail,
        temp_crash_file,
        config.run_timeout,
    )

    # log the crash information to that executables dedicated csv file
    logger.info(
        f"Result of running file {crash_detail.executable_name}: {return_code}."
    )
    logger.info(f"Updating the results csv for {crash_detail.executable_name}")
    log_crash_information(
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
    log_results(results, config.patch_eval_results_full_path)


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
    EVAL_SVC_START_TIMESTAMP: Final[str] = get_current_timestamp()

    # create timestamped directories
    _timestamped_patch_eval_results_path: Final[str] = os.path.join(
        config.patch_eval_results_full_path, EVAL_SVC_START_TIMESTAMP
    )
    # _timestamped_executables_full_path: Final[str] = os.path.join(
    #     config.executables_full_path, EVAL_SVC_START_TIMESTAMP
    # )

    # log some info, make the directories if they DNE
    logger.info("AppVersion: " + config.version)
    os.makedirs(_timestamped_patch_eval_results_path, exist_ok=True)
    logger.info("Creating executables directory: " + config.executables_full_path)
    os.makedirs(config.executables_full_path, exist_ok=True)
    logger.info(
        "Creating temporary crash files directory: " + config.temp_crashes_full_path
    )
    os.makedirs(config.temp_crashes_full_path, exist_ok=True)

    # list of files successfully compiled and a dict for the results of each
    executables_to_process, results = prep_executables_for_evaluation(
        config.executables_full_path,
        config.patched_codes_path,
        config.compiler_tool_full_path,
        config.compiler_warning_flags,
        config.compiler_feature_flags,
        config.compile_timeout,
    )

    # initialize the message broker client
    message_broker_client: MessageBrokerClient = MessageBrokerClient(
        config.message_broker_host,
        config.message_broker_port,
        logger,
    )

    event_loop = asyncio.get_running_loop()

    # Start the consumer coroutine as a background task.
    consumer_task = asyncio.create_task(crash_detail_consumer())

    # subscribe to topic
    message_broker_client.consume(
        config.autopatch_crash_detail_input_topic, on_consume_crash_detail
    )

    # Keep the program running indefinitely, waiting for more events.
    await asyncio.Future()  # This future will never complete.


# Run the event loop
asyncio.run(main())
