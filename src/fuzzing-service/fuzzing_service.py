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

from autopatchdatatypes import CrashDetail
from autopatchpubsub import MessageBrokerClient
from autopatchshared import init_logging, load_config_as_json, get_current_timestamp
from cloudevents.conversion import to_json
from cloudevents.http import CloudEvent
from fuzz_svc_config import FuzzSvcConfig

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_FUZZ_SVC_CONFIG: Final[str] = "FUZZ_SVC_CONFIG"
config: FuzzSvcConfig

# before configuration is loaded, use the default logger
logger = logging.getLogger(__name__)


async def map_crash_detail_as_cloudevent(crash_detail: CrashDetail) -> CloudEvent:
    """
    Maps a CrashDetail instance to a CloudEvent Occurence.

    Parameters:
        crash (CrashDetail): The crash detail to be mapped.

    Returns:
        CloudEvent: The corresponding CloudEvent Occurence.
    """
    if crash_detail is None or any(
        value is None
        for value in [
            crash_detail.executable_name,
            crash_detail.base64_message,
            crash_detail.is_input_from_file,
        ]
    ):
        logger.error("Invalid crash_detail object or one of its values is None.")
        logger.debug(f"CrashDetail: {crash_detail}")
        raise ValueError("Invalid crash_detail object or one of its values is None.")

    attributes = {
        "type": "autopatch.crashdetail",
        "source": "autopatch.fuzzing-service",
        "subject": crash_detail.executable_name,
        "time": get_current_timestamp(),
    }

    data = {
        "executable_name": crash_detail.executable_name,
        "crash_detail_base64": crash_detail.base64_message,
        "is_input_from_file": crash_detail.is_input_from_file,
    }

    event = CloudEvent(attributes, data)
    return event


def compile_program_run_fuzzer(
    program_name: str,
    input_codebase_path: str,
    program_path: str,
    fuzzer_compatible_executables_output_directory_path: str,
    fuzzer_compiler_full_path: str,
    fuzzer_full_path: str,
    fuzzer_seed_input_path: str,
    fuzzer_output_path: str,
    fuzzer_timeout: int,
    isInputFromFile: bool,
) -> bool:
    """
    Compile the C source file for AFL fuzzing and run the fuzzer.
    Returns True if the fuzzer appears to have started successfully.
    """
    src_path = os.path.join(input_codebase_path, program_path)

    # Name of the executable that was compiled with the fuzzer's version of GCC
    executable_name = os.path.join(
        fuzzer_compatible_executables_output_directory_path, program_name + ".afl"
    )
    # Compile using AFL's compiler
    warn_flags = config.compiler_warning_flags
    feature_flags = config.compiler_feature_flags
    compile_command = f"{fuzzer_compiler_full_path} {warn_flags} {feature_flags} {src_path} -o {executable_name}"
    logger.debug(f"Compile command: {compile_command}")
    try:
        result = subprocess.run(
            compile_command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=fuzzer_timeout,
            shell=True,
            check=True,
        )
        logger.debug(f"Fuzzer compile output: {result.stdout + result.stderr}")
    except (OSError, subprocess.CalledProcessError) as e:
        return_code = getattr(e, "returncode", "N/A")
        output = getattr(e, "output", "N/A")
        logger.error(f"Failed to start compiler subprocess. Return Code: {return_code}")
        logger.debug(f"Output of compiler subprocess: {output}")
        return False
    except Exception as e:
        logger.error(f"Error running fuzzer: {e}")
        return False

    # Prepare the fuzzing command
    fuzz_command = (
        f"{fuzzer_full_path} -m {config.afl_tool_child_process_memory_limit_mb} -i {fuzzer_seed_input_path} -o {fuzzer_output_path}/{program_name} "
        f"-t {fuzzer_timeout} {executable_name}"
    )

    if isInputFromFile:
        fuzz_command += " @@"
    logger.debug(f"Running Fuzzer with run command: {fuzz_command}")
    try:
        fuzz_start_timestamp = get_current_timestamp()
        # Launch the process in a new session so that it gets its own process group
        process = subprocess.Popen(
            fuzz_command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            shell=True,
            start_new_session=True,  # This creates a new process group
        )
        time.sleep(0.5)  # Give the process a moment to start

        # Check if process started successfully
        if process.poll() is not None:
            logger.error("Fuzzer subprocess failed to start.")
        else:
            logger.info(
                f"Fuzzer process started with PID: {process.pid}. Waiting for it to finish."
            )
            # Wait for process to complete or timeout
            stdout, stderr = process.communicate(timeout=fuzzer_timeout)
            logger.debug(f"Fuzzer command output: {stdout} {stderr}")
            # Kill the entire process group to ensure that all subprocesses are terminated.
            logger.info("Killing the fuzzer process group.")
            os.killpg(os.getpgid(process.pid), signal.SIGTERM)
            stdout, stderr = process.communicate()
            logger.debug(f"Closed subprocess group output: {stdout} {stderr}")
    except subprocess.TimeoutExpired:
        logger.info(f"Fuzzer run timed out after {fuzzer_timeout} seconds as expected.")
        # Kill the entire process group to ensure that all subprocesses are terminated.
        logger.info("Killing the fuzzer process group.")
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        stdout, stderr = process.communicate()
        logger.debug(f"Closed subprocess group output: {stdout} {stderr}")
        return True
    except OSError as e:
        return_code = getattr(e, "returncode", "N/A")
        output = getattr(e, "output", "N/A")
        logger.error(f"Failed to start fuzzer subprocess. Return Code: {return_code}")
        logger.debug(f"Output of fuzzer subprocess: {output}")
    except Exception as e:
        logger.error(f"Error running fuzzer: {e}")

    time_delta = datetime.fromisoformat(
        get_current_timestamp()
    ) - datetime.fromisoformat(fuzz_start_timestamp)
    logger.info(
        f"Fuzzer did not time out as expected. Fuzzer run time elapsed: {time_delta}"
    )

    return False


def extract_crashes(
    fuzzer_output_path: str, executable_name: str, timeout: int, isInputFromFile: bool
) -> List[CrashDetail]:
    """
    Examine the fuzzer output directory for crash inputs.
    Returns a list of crash file paths (if isInputFromFile is True) or raw byte contents.
    """

    # add 'default' to the path to match the AFL++ output directory structure
    crash_dir = os.path.join(
        f"{fuzzer_output_path}", f"{executable_name}", "default", "crashes"
    )
    crashes = []
    try:
        for crash_file in os.listdir(crash_dir):
            if crash_file == "README.txt":
                continue
            file_path = os.path.join(crash_dir, crash_file)
            if isInputFromFile:
                # Convert file encoding to UTF-8 (if necessary)
                convert_command = (
                    f"iconv -f ISO-8859-1 -t UTF-8 '{file_path}' > '{file_path}.utf8'"
                )
                try:
                    subprocess.run(
                        convert_command,
                        stderr=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        timeout=timeout,
                        universal_newlines=True,
                        shell=True,
                        check=True,
                    )
                    os.replace(f"{file_path}.utf8", file_path)
                except subprocess.TimeoutExpired:
                    logger.error(
                        f"iconv subprocess failed via time out after {timeout} seconds."
                    )
                    continue
                except subprocess.CalledProcessError as e:
                    logger.error(
                        f"iconv subprocess failed with return code {e.returncode}."
                    )
                    logger.debug(f"Output of iconv subprocess: {e.output}")
                    continue
                except Exception as e:
                    logger.error(f"Error converting crash file encoding: {e}")
                    continue
                crashes.append(
                    base64.b64encode(file_path.encode("utf-8")).decode("utf-8")
                )
            else:
                with open(file_path, "rb") as f:
                    crashes.append(base64.b64encode(f.read()).decode("utf-8"))
    except FileNotFoundError:
        logger.error(
            "No crashes directory found. Fuzzer might not have detected any crashes."
        )

    return [CrashDetail(executable_name, crash, isInputFromFile) for crash in crashes]


def write_crashes_csv(crash_details: List[CrashDetail], csv_path: str) -> None:
    """
    Process crash outputs by appending lines to the appropriate CSV file.

    Each line contains the timestamp, executable name, and crash detail.
    """

    # Ensure the output directory exists.
    os.makedirs(os.path.dirname(csv_path), exist_ok=True)

    # Check if the file exists and is not empty.
    write_header = not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0

    with open(csv_path, "a", encoding="utf-8") as f:
        if write_header:
            f.write("timestamp,executable_name,crash_detail_base64,isInputFromFile\n")
        for crash in crash_details:
            logger.info(f"  - {crash}")
            timestamp = get_current_timestamp()
            f.write(
                f"{timestamp},{crash.executable_name},{crash.base64_message},{crash.is_input_from_file}\n"
            )


async def map_crashdetails_as_cloudevents(
    crash_details: List[CrashDetail],
) -> List[CloudEvent]:
    if len(crash_details) > config.concurrency_threshold:
        # Run in parallel
        tasks = [map_crash_detail_as_cloudevent(detail) for detail in crash_details]
        results = await asyncio.gather(*tasks)
    else:
        # Run sequentially
        results = [
            await map_crash_detail_as_cloudevent(detail) for detail in crash_details
        ]

    return results


async def produce_output(crash_details: List[CrashDetail]) -> None:

    async def produce_event(event: CloudEvent) -> None:
        # flake8 flags the following as F821 because it doesn't recognize the global variable
        logger.debug(
            f"Producing on Topic: {config.fuzz_svc_output_topic}"  # noqa: F821
        )
        logger.debug(f"Producing CloudEvent: {event}")
        message_broker_client.publish(
            config.fuzz_svc_output_topic, to_json(event).decode("utf-8")  # noqa: F821
        )

    crash_details_cloud_events: List[CloudEvent] = (
        await map_crashdetails_as_cloudevents(crash_details)
    )
    message_broker_client: Final[MessageBrokerClient] = MessageBrokerClient(
        config.message_broker_host, config.message_broker_port, logger
    )

    logger.info(f"Producing {len(crash_details_cloud_events)} CloudEvents.")
    if len(crash_details_cloud_events) > config.concurrency_threshold:
        # Run in parallel using asyncio.gather
        tasks = [produce_event(event) for event in crash_details_cloud_events]
        await asyncio.gather(*tasks)
    else:
        # Run sequentially
        for event in crash_details_cloud_events:
            await produce_event(event)

    csv_path: Final[str] = os.path.join(config.fuzz_svc_output_path, "crashes.csv")
    write_crashes_csv(crash_details, csv_path)


def load_config(json_config_full_path: str) -> FuzzSvcConfig:
    config = load_config_as_json(json_config_full_path, logger)
    return FuzzSvcConfig(**config)


async def main():
    global config, logger

    config_full_path = os.environ.get(CONST_FUZZ_SVC_CONFIG)
    if not config_full_path:
        logger.error(
            f"Error: The environment variable {CONST_FUZZ_SVC_CONFIG} is not set or is empty."
        )
        sys.exit(1)

    config = load_config(config_full_path)
    logger = init_logging(config.logging_config, config.appname)

    FUZZ_SVC_START_TIMESTAMP: Final[str] = get_current_timestamp()

    _fuzz_svc_input_codebase_path: Final[str] = config.fuzz_svc_input_codebase_path
    _fuzzer_tool_timeout_seconds: Final[int] = config.fuzzer_tool_timeout_seconds
    _afl_tool_full_path: Final[str] = config.afl_tool_full_path
    _afl_tool_seed_input_path: Final[str] = config.afl_tool_seed_input_path
    _afl_tool_compiled_binary_executables_output_path: Final[str] = (
        config.afl_tool_compiled_binary_executables_output_path
    )
    _afl_tool_output_path: Final[str] = os.path.join(
        config.afl_tool_output_path, FUZZ_SVC_START_TIMESTAMP
    )
    _afl_compiler_tool_full_path: Final[str] = config.afl_compiler_tool_full_path

    logger.info("AppVersion: " + config.version)
    logger.info("Fuzzer tool name: " + config.fuzzer_tool_name)
    logger.info("Fuzzer tool version: " + config.fuzzer_tool_version)

    logger.info("Creating AFL output directory: " + _afl_tool_output_path)
    os.makedirs(_afl_tool_output_path, exist_ok=True)

    # Process each C source file in the codebase directory
    _source_files = os.listdir(_fuzz_svc_input_codebase_path)
    logger.info(
        f"Found {len(_source_files)} source files in {_fuzz_svc_input_codebase_path}"
    )
    for source_file in _source_files:
        if not source_file.endswith(".c"):
            continue

        logger.info(
            f"Processing: {os.path.join(_fuzz_svc_input_codebase_path, source_file)}"
        )
        executable_name = os.path.splitext(source_file)[0]
        # Optionally, decide if the target takes input from a file (e.g. based on naming convention)
        isInputFromFile = executable_name.endswith("_f")

        # Step 1: Run the AFL fuzzer
        fuzzer_started = compile_program_run_fuzzer(
            executable_name,
            _fuzz_svc_input_codebase_path,
            source_file,
            _afl_tool_compiled_binary_executables_output_path,
            _afl_compiler_tool_full_path,
            _afl_tool_full_path,
            _afl_tool_seed_input_path,
            _afl_tool_output_path,
            _fuzzer_tool_timeout_seconds,
            isInputFromFile,
        )
        if fuzzer_started:
            logger.info(f"Fuzzer started for {source_file}.")
        else:
            logger.info(f"Fuzzer did not start properly for {source_file}.")

        # Step 2: Extract crash inputs (if any)
        logger.info("Entering step 2: extract crash inputs")
        crash_details = extract_crashes(
            _afl_tool_output_path,
            executable_name,
            config.iconv_tool_timeout,
            isInputFromFile,
        )

        # Process the crash outputs
        if crash_details:
            logger.info(f"Found {len(crash_details)} crash(es) for {source_file}:")
            await produce_output(crash_details)
        else:
            logger.info(f"No crashes found for {source_file}.")

    FUZZ_SVC_END_TIMESTAMP: Final[str] = get_current_timestamp()
    time_delta = datetime.fromisoformat(
        FUZZ_SVC_END_TIMESTAMP
    ) - datetime.fromisoformat(FUZZ_SVC_START_TIMESTAMP)
    logger.info(f"Total Processing Time Elapsed: {time_delta}")
    logger.info("Processing complete, exiting.")


# Run the event loop
asyncio.run(main())
