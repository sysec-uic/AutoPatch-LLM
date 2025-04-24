import asyncio
import base64
import json
import logging
import os
import signal
import subprocess
import sys
import time
from datetime import datetime
from typing import Final, List

from cloudevents.conversion import to_json
from cloudevents.http import CloudEvent
from fuzz_svc_config import FuzzSvcConfig

from autopatchdatatypes import CrashDetail
from autopatchpubsub import MessageBrokerClient
from autopatchshared import (
    get_current_timestamp,
    init_logging,
    load_config_as_json,
    make_compile,
)

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


def compile_program(
    program_source_fully_qualified_path: str,
    output_executable_fully_qualified_path: str,
    fuzzer_compiler_full_path: str,
    timeout: int,
) -> bool:
    """
    Compile the C source file for AFL fuzzing and run the fuzzer.
    Returns True if the fuzzer appears to have started successfully.
    """

    # Compile using AFL's compiler
    warn_flags = config.compiler_warning_flags
    feature_flags = config.compiler_feature_flags
    compile_command = (
        f"{fuzzer_compiler_full_path} "
        f"{warn_flags} "
        f"{feature_flags} "
        f"{program_source_fully_qualified_path} "
        f"-o {output_executable_fully_qualified_path}"
    )
    logger.debug(f"Compile command: {compile_command}")
    try:
        result = subprocess.run(
            compile_command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            shell=True,
            check=True,
        )
        logger.debug(f"Fuzzer compile output: {result.stdout + result.stderr}")
        return True
    except (OSError, subprocess.CalledProcessError) as e:
        return_code = getattr(e, "returncode", "N/A")
        output = getattr(e, "output", "N/A")
        logger.error(f"Failed to start compiler subprocess. Return Code: {return_code}")
        logger.debug(f"Output of compiler subprocess: {output}")
        return False
    except Exception as e:
        logger.error(f"Error running fuzzer: {e}")
        return False


def run_fuzzer(
    fuzzer_full_path: str,
    fuzzer_seed_input_path: str,
    fuzzer_timeout: int,
    isInputFromFile: bool,
    fully_qualified_fuzzer_tool_output_path: str,
    output_executable_fully_qualified_path: str,
) -> bool:
    """
    Runs the specified fuzzer tool in a subprocess with
    given configuration parameters and monitors its execution.
    This function constructs a command to run a fuzzer tool
    with options such as memory limit, input directory, output
    directory, timeout, and a target executable. It handles
    process startup, monitors its execution, and manages a timeout
    scenario by forcefully terminating the process group
    if the fuzzer run exceeds the specified time.
    Args:
        fuzzer_full_path (str): The full filesystem path
            to the fuzzer executable.
        fuzzer_seed_input_path (str): The path to the
            directory containing seed inputs for the fuzzer.
        fuzzer_timeout (int): Maximum allowed execution
            time (in seconds) for the fuzzer run.
        isInputFromFile (bool): Indicates whether the
            fuzzer should read input from a file (appending " @@").
        fully_qualified_fuzzer_tool_output_path (str):
            The directory path where the fuzzer tool's
            output should be stored.
        output_executable_fully_qualified_path (str):
            The full path to the executable that
            the fuzzer will target.
    Returns:
        bool: Returns True if the fuzzer run times out
            and is terminated as expected, otherwise False.
    Exceptions:
        OSError: If there is an error starting
            the fuzzer subprocess.
        Exception: For any other errors encountered
            during the fuzzer's execution.
    """

    fuzz_command = (
        f"{fuzzer_full_path} "
        f"-m {config.afl_tool_child_process_memory_limit_mb} "
        f"-i {fuzzer_seed_input_path} "
        f"-o {fully_qualified_fuzzer_tool_output_path} "
        f"-t {fuzzer_timeout} "
        f"{output_executable_fully_qualified_path}"
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

        logger.info(
            f"Fuzzer process started with PID: {process.pid}. Waiting for it to finish."
        )
        # Wait for process to complete or timeout
        stdout, stderr = process.communicate(timeout=fuzzer_timeout)
        logger.debug(f"Fuzzer command output: {stdout} {stderr}")
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
    fully_qualified_crash_directory_path: str,
    executable_name: str,
    timeout: int,
    isInputFromFile: bool,
) -> List[CrashDetail]:
    """
    Examine the fuzzer output directory for crash inputs.
    Returns a list of crash file paths (if isInputFromFile is True) or raw byte contents.
    """

    crashes = []
    try:
        for crash_file in os.listdir(fully_qualified_crash_directory_path):
            if crash_file == "README.txt":
                continue
            file_path = os.path.join(fully_qualified_crash_directory_path, crash_file)
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
        await message_broker_client.publish(
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
    _make_tool_full_path: Final[str] = config.make_tool_full_path

    logger.info("AppVersion: " + config.version)
    logger.info("Fuzzer tool name: " + config.fuzzer_tool_name)
    logger.info("Fuzzer tool version: " + config.fuzzer_tool_version)

    # Process each C source file in the codebase directory
    _source_files = os.listdir(_fuzz_svc_input_codebase_path)
    logger.info(
        f"Found {len(_source_files)} source files in {_fuzz_svc_input_codebase_path}"
    )

    # changes to make: need to check if it's a directory
    # within the directory, check for makefile
    # for afl compilation: need to source the afl compiler path
    # for fuzz target run: need to source the afl fuzzer path, the input and output directories
    # put the executable in assets instead of bin?

    # for regular compilation: source the compiler, plus for execution need to source the input of the crashes althoguth this is
    # maybe just acquired from the crash detail object?

    for file_name in _source_files:
        # get the full path of the file or the project directory
        file_name_fully_qualified_path = os.path.join(
            _fuzz_svc_input_codebase_path, file_name
        )
        logger.info(f"Processing project: {file_name_fully_qualified_path}")

        if not os.path.isdir(file_name_fully_qualified_path):
            isInputFromFile = file_name.endswith("_f")

            # Step 1: compile program with afl
            executable_name = file_name[:-2]
            output_executable_directory_path = os.path.join(
                _afl_tool_compiled_binary_executables_output_path, executable_name
            )
            os.makedirs(output_executable_directory_path, exist_ok=True)

            output_executable_fully_qualified_path = os.path.join(
                output_executable_directory_path,
                executable_name + ".afl",
            )
            # compile the program
            compiled_program = compile_program(
                file_name_fully_qualified_path,
                output_executable_fully_qualified_path,
                _afl_compiler_tool_full_path,
                10,
            )
            # if fail then move on to next input
            if not compiled_program:
                logger.info(f"File {executable_name} failed to compile.")
                continue

            fully_qualified_fuzzer_tool_output_path = os.path.join(
                _afl_tool_output_path, executable_name
            )
            os.makedirs(fully_qualified_fuzzer_tool_output_path, exist_ok=True)

            fuzzer_started = run_fuzzer(
                _afl_tool_full_path,
                _afl_tool_seed_input_path,
                _fuzzer_tool_timeout_seconds,
                isInputFromFile,
                fully_qualified_fuzzer_tool_output_path,
                output_executable_fully_qualified_path,
            )

            if fuzzer_started:
                logger.info(f"Fuzzer started for {file_name}.")
            else:
                logger.info(f"Fuzzer did not start properly for {file_name}.")
        # if the source code is directoried
        else:

            executable_name = file_name
            output_executable_directory_path = os.path.join(
                _afl_tool_compiled_binary_executables_output_path, executable_name
            )
            os.makedirs(output_executable_directory_path, exist_ok=True)

            output_executable_fully_qualified_path = os.path.join(
                output_executable_directory_path,
                executable_name + ".afl",
            )
            # compile
            make_compiled = make_compile(
                file_name_fully_qualified_path,
                output_executable_fully_qualified_path,
                _afl_compiler_tool_full_path,
                _make_tool_full_path,
                logger,
            )
            if not make_compiled:
                logger.info(f"Project {executable_name} did not compile using Make.")
                continue
            fully_qualified_fuzzer_tool_output_path = os.path.join(
                _afl_tool_output_path, executable_name
            )

            if not make_compiled:
                logger.info(f"Compilation for project {file_name} failed.")
                continue

            try:
                with open(
                    os.path.join(file_name_fully_qualified_path, "config.json"), "r"
                ) as project_config:
                    project_config_vals = json.load(project_config)
                    isInputFromFile = project_config_vals["inputFromFile"]
            except Exception as e:
                logger.error(f"Problem loading the project config file: {e}")
                logger.info(
                    f"Cannot discern inputFromFile value for project {file_name_fully_qualified_path}. Skipping."
                )
                continue

            os.makedirs(fully_qualified_fuzzer_tool_output_path, exist_ok=True)
            fuzzer_started = run_fuzzer(
                _afl_tool_full_path,
                _afl_tool_seed_input_path,
                _fuzzer_tool_timeout_seconds,
                isInputFromFile,
                fully_qualified_fuzzer_tool_output_path,
                output_executable_fully_qualified_path,
            )
            if fuzzer_started:
                logger.info(f"Fuzzer started for {file_name}.")
            else:
                logger.info(f"Fuzzer did not start properly for {file_name}.")

        # get output directory fully qualified path
        fully_qualified_crash_directory_path = os.path.join(
            fully_qualified_fuzzer_tool_output_path, "default", "crashes"
        )
        # Step 2: Extract crash inputs (if any)
        logger.info("Entering step 2: extract crash inputs")
        crash_details = extract_crashes(
            fully_qualified_crash_directory_path,
            executable_name,
            config.iconv_tool_timeout,
            isInputFromFile,
        )

        # Process the crash outputs
        if crash_details:
            logger.info(f"Found {len(crash_details)} crash(es) for {file_name}:")
            await produce_output(crash_details)
        else:
            logger.info(f"No crashes found for {file_name}.")
        continue

    FUZZ_SVC_END_TIMESTAMP: Final[str] = get_current_timestamp()
    time_delta = datetime.fromisoformat(
        FUZZ_SVC_END_TIMESTAMP
    ) - datetime.fromisoformat(FUZZ_SVC_START_TIMESTAMP)
    logger.info(f"Total Processing Time Elapsed: {time_delta}")
    logger.info("Processing complete, exiting.")


if __name__ == "__main__":
    # Run the event loop
    asyncio.run(main())
