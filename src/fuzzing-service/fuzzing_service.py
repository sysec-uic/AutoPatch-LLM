import json
import logging
import logging.config
import os
import signal
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Final

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_FUZZ_SVC_CONFIG: Final[str] = "FUZZ_SVC_CONFIG"

config = dict()
logger = logging.getLogger(__name__)


@dataclass
class Config:
    version: str
    appname: str
    logging_config: str
    fuzz_svc_input_codebase_path: str
    fuzz_svc_output_path: str
    fuzz_svc_output_topic: str
    compiler_warning_flags: str
    compiler_feature_flags: str
    fuzzer_tool_name: str
    fuzzer_tool_timeout_seconds: int
    fuzzer_tool_version: str
    afl_tool_full_path: str
    afl_tool_seed_input_path: str
    afl_tool_output_path: str
    afl_tool_child_process_memory_limit_mb: int
    afl_tool_compiled_binary_executables_output_path: str
    afl_compiler_tool_full_path: str
    iconv_tool_timeout: int
    mqtt_host: str
    mqtt_port: int = 1833


def init_logging(logging_config: str, appname: str) -> logging.Logger:
    """
    Initializes logging from a JSON configuration file.

    If the JSON file cannot be loaded or the configuration is invalid,
    a basic logging configuration is used as a fallback.

    Parameters:
        logging_config (str): Path to the JSON file with logging configuration.
        appname (str): Name of the application logger.

    Returns:
        logging.Logger: Configured logger instance.
    """
    try:
        # Check if the configuration file exists
        if not os.path.exists(logging_config):
            raise FileNotFoundError(
                f"Logging configuration file '{logging_config}' not found."
            )

        # Load the JSON configuration from the file
        with open(logging_config, "r") as config_file:
            config_dict = json.load(config_file)

        # Apply the logging configuration
        logging.config.dictConfig(config_dict)

    except FileNotFoundError as fnf_error:
        print(fnf_error)
        print("Falling back to basic logging configuration.")
        logging.basicConfig(level=logging.INFO)

    except json.JSONDecodeError as json_error:
        print(f"Error decoding JSON from {logging_config}: {json_error}")
        print("Falling back to basic logging configuration.")
        logging.basicConfig(level=logging.INFO)

    except Exception as e:
        print(f"Unexpected error while loading logging configuration: {e}")
        print("Falling back to basic logging configuration.")
        logging.basicConfig(level=logging.INFO)

    # Get and return the logger for the specified application name
    logger = logging.getLogger(appname)
    logger.info("Logger initialized successfully.")
    return logger


def load_config() -> dict:
    """
    Load the configuration from a JSON file.  Does not support loading config from a YAML file.
    """
    # Read the environment variable
    config_path = os.environ.get(CONST_FUZZ_SVC_CONFIG)
    if not config_path:
        logger.error(
            "Error: The environment variable 'FUZZ_SVC_CONFIG' is not set or is empty."
        )
        sys.exit(1)

    try:
        # Open the file with UTF-8 encoding
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        logger.error(f"Error: The config file at '{config_path}' was not found.")
        sys.exit(1)
    except UnicodeDecodeError as e:
        logger.error(
            f"Error: The config file at '{config_path}' is not a valid UTF-8 text file: {e}"
        )
        sys.exit(1)
    except json.JSONDecodeError as e:
        logger.error(
            f"Error: The config file at '{config_path}' contains invalid JSON: {e}"
        )
        sys.exit(1)
    except Exception as e:
        logger.error(
            f"Error: An unexpected error occurred while loading the config file: {e}"
        )
        sys.exit(1)

    return config


def run_fuzzer(
    executable_name: str,
    codebase_path: str,
    program_path: str,
    executables_afl_path: str,
    fuzzer_compiler_full_path: str,
    fuzzer_full_path: str,
    fuzzer_seed_input_path: str,
    fuzzer_output_path: str,
    fuzzer_timeout: int,
    inputFromFile,
    isCodebase=True,
):
    """
    Compile the C source file for AFL fuzzing and run the fuzzer.
    Returns True if the fuzzer appears to have started successfully.
    """
    if isCodebase:
        src_path = os.path.join(codebase_path, program_path)
    else:
        src_path = program_path

    afl_executable = os.path.join(executables_afl_path, executable_name + ".afl")
    # Compile using AFL's compiler
    compile_command = f"{fuzzer_compiler_full_path} {config["compiler_warning_flags"]} {config["compiler_feature_flags"]} {src_path} -o {afl_executable}"
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
    except subprocess.CalledProcessError as e:
        logger.error(f"Fuzzer subprocess failed with return code {e.returncode}.")
        logger.debug(f"Output of fuzzer subprocess: {e.output}")
        return False
    except Exception as e:
        logger.error(f"Error compiling with AFL: {e}")
        return False

    logger.debug(f"Fuzzer compile command: {compile_command}")

    # Prepare the fuzzing command
    fuzz_command = (
        f"{fuzzer_full_path} -m {config['afl_tool_child_process_memory_limit_mb']} -i {fuzzer_seed_input_path} -o {fuzzer_output_path}/{executable_name} "
        f"-t {fuzzer_timeout} {afl_executable}"
    )
    if inputFromFile:
        fuzz_command += " @@"
    logger.debug(f"Running Fuzzer with run command: {fuzz_command}")
    try:
        # Launch the process in a new session so that it gets its own process group
        process = subprocess.Popen(
            fuzz_command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            shell=True,
            start_new_session=True,  # This creates a new process group
        )
        process.communicate(timeout=fuzzer_timeout)
        stdout, stderr = process.communicate(timeout=fuzzer_timeout)
        logger.debug(f"Fuzzer command output: {stdout} {stderr}")
    except subprocess.CalledProcessError as e:
        logger.error(f"Fuzzer subprocess failed with return code {e.returncode}.")
        logger.debug(f"Output of fuzzer subprocess: {e.output}")
        return False
    except subprocess.TimeoutExpired:
        # Fuzzer may run indefinitely; timeout is expected.
        logger.info(f"Fuzzer run timed out after {fuzzer_timeout} seconds as expected.")
        # Kill the entire process group to ensure that all subprocesses are terminated.
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        # process.communicate()  # Wait for process to finish cleanup
        stdout, stderr = process.communicate(timeout=fuzzer_timeout)
        logger.debug(f"Close subprocess group command output: {stdout} {stderr}")
    except Exception as e:
        logger.error(f"Error running fuzzer: {e}")
        return False

    # # Verify that the fuzzer started by checking for the "fuzzer_stats" file
    if os.path.exists(f"{fuzzer_output_path}/{executable_name}/fuzzer_stats"):
        return True
    return False


def extract_crashes(
    fuzzer_output_path: str, executable_name: str, timeout: int, inputFromFile: bool
):
    """
    Examine the fuzzer output directory for crash inputs.
    Returns a list of crash file paths (if inputFromFile is True) or raw byte contents.
    """
    crash_dir = os.path.join(f"{fuzzer_output_path}", f"{executable_name}", "crashes")
    crashes = []
    try:
        for crash_file in os.listdir(crash_dir):
            if crash_file == "README.txt":
                continue
            file_path = os.path.join(crash_dir, crash_file)
            if inputFromFile:
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
                crashes.append(file_path)
            else:
                with open(file_path, "rb") as f:
                    crashes.append(f.read())
    except FileNotFoundError:
        logger.error(
            "No crashes directory found. Fuzzer might not have detected any crashes."
        )

    return crashes


def write_crashes_csv(
    executable_name: str, crashes: list, csv_path: str, inputFromFile: bool
) -> None:
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
            f.write("timestamp,executable_name,crash_detail,inputFromFile\n")
        for crash in crashes:
            logger.info(f"  - {crash}")
            timestamp = datetime.now().isoformat(timespec="seconds")
            if inputFromFile:
                # Crash is a file path.
                line = f"{timestamp},{executable_name},{crash},True\n"
            else:
                # Crash is raw bytes; convert to hexadecimal string.
                crash_hex = crash.hex()
                line = f"{timestamp},{executable_name},{crash_hex},False\n"
            f.write(line)


def produce_output(executable_name: str, crashes: list, inputFromFile: bool) -> None:
    csv_path: Final[str] = os.path.join(config["fuzz_svc_output_path"], "crashes.csv")
    write_crashes_csv(executable_name, crashes, csv_path, inputFromFile)


def main():
    global config, logger

    config = load_config()
    logger = init_logging(config["logging_config"], config["appname"])

    FUZZ_SVC_START_TIMESTAMP: Final[str] = datetime.now().isoformat(timespec="seconds")

    _fuzz_svc_input_codebase_path: Final[str] = config["fuzz_svc_input_codebase_path"]
    _fuzzer_tool_timeout_seconds: Final[int] = config["fuzzer_tool_timeout_seconds"]
    _afl_tool_full_path: Final[str] = config["afl_tool_full_path"]
    _afl_tool_seed_input_path: Final[str] = config["afl_tool_seed_input_path"]
    _afl_tool_compiled_binary_executables_output_path: Final[str] = config[
        "afl_tool_compiled_binary_executables_output_path"
    ]
    _afl_tool_output_path: Final[str] = os.path.join(
        config["afl_tool_output_path"], FUZZ_SVC_START_TIMESTAMP
    )
    _afl_compiler_tool_full_path: Final[str] = config["afl_compiler_tool_full_path"]

    logger.info("AppVersion: " + config["version"])
    logger.info("Fuzzer tool name: " + config["fuzzer_tool_name"])
    logger.info("Fuzzer tool version: " + config["fuzzer_tool_version"])

    logger.info("Creating AFL output directory: " + _afl_tool_output_path)
    os.makedirs(_afl_tool_output_path, exist_ok=True)

    # Process each C source file in the codebase directory
    for source_file in os.listdir(_fuzz_svc_input_codebase_path):
        if not source_file.endswith(".c"):
            continue

        logger.info(
            f"Processing: {os.path.join(_fuzz_svc_input_codebase_path, source_file)}"
        )
        executable_name = os.path.splitext(source_file)[0]
        # Optionally, decide if the target takes input from a file (e.g. based on naming convention)
        inputFromFile = executable_name.endswith("_f")

        # Step 1: Run the AFL fuzzer
        fuzzer_started = run_fuzzer(
            executable_name,
            _fuzz_svc_input_codebase_path,
            source_file,
            _afl_tool_compiled_binary_executables_output_path,
            _afl_compiler_tool_full_path,
            _afl_tool_full_path,
            _afl_tool_seed_input_path,
            _afl_tool_output_path,
            _fuzzer_tool_timeout_seconds,
            inputFromFile,
            isCodebase=True,
        )
        if fuzzer_started:
            logger.info(f"Fuzzer started for {source_file}.")
        else:
            logger.info(f"Fuzzer did not start properly for {source_file}.")

        # Step 2: Extract crash inputs (if any)
        logger.info("Entering step 3: extract crash inputs")
        crashes = extract_crashes(
            _afl_tool_output_path,
            executable_name,
            config["iconv_tool_timeout"],
            inputFromFile,
        )

        # Process the crash outputs by appending to the appropriate CSV file.
        if crashes:
            logger.info(f"Found {len(crashes)} crash(es) for {source_file}:")
            produce_output(executable_name, crashes, inputFromFile)
        else:
            logger.info(f"No crashes found for {source_file}.")

    FUZZ_SVC_END_TIMESTAMP: Final[str] = datetime.now().isoformat(timespec="seconds")
    time_delta = datetime.fromisoformat(
        FUZZ_SVC_END_TIMESTAMP
    ) - datetime.fromisoformat(FUZZ_SVC_START_TIMESTAMP)
    logger.info(f"Total Processing Time Elapsed: {time_delta}")
    logger.info("Processing complete, exiting.")


if __name__ == "__main__":
    main()
