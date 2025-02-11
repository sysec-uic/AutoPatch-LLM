import json
import logging
import logging.config
import os
import subprocess
import sys
from dataclasses import dataclass
from typing import Final

# Other settings
no_stack_protector: Final[str] = "-fno-stack-protector"
timeout: Final[int] = 120  # seconds

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_FUZZ_SVC_CONFIG: Final[str] = "FUZZ_SVC_CONFIG"

config = dict()
logger = logging.Logger


@dataclass
class Config:
    version: str
    appname: str
    logging_config: str
    fuzz_svc_input_codebase_path: str
    fuzz_svc_output_topic: str
    compiled_binary_executables_output_path: str
    compiler_tool_full_path: str
    fuzzer_tool_name: str
    fuzzer_tool_version: str
    afl_tool_full_path: str
    afl_tool_seed_input_path: str
    afl_tool_output_path: str
    afl_tool_compiled_binary_executables_output_path: str
    afl_compiler_tool_full_path: str
    mqtt_host: str
    mqtt_port: int = 1833
    debug: bool = False


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
        print(
            "Error: The environment variable 'FUZZ_SVC_CONFIG' is not set or is empty."
        )
        sys.exit(1)

    try:
        # Open the file with UTF-8 encoding
        with open(config_path, "r", encoding="utf-8") as f:
            config = json.load(f)
    except FileNotFoundError:
        print(f"Error: The config file at '{config_path}' was not found.")
        sys.exit(1)
    except UnicodeDecodeError as e:
        print(
            f"Error: The config file at '{config_path}' is not a valid UTF-8 text file: {e}"
        )
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"Error: The config file at '{config_path}' contains invalid JSON: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: An unexpected error occurred while loading the config file: {e}")
        sys.exit(1)

    return config


def run_sanitizer(
    program_path: str, compiler_output_directory: str, output_executable_name: str
):
    """
    Compile the given C source file with AddressSanitizer enabled.
    Returns a tuple: (True/False depending on successful compilation, compile output log).
    """

    warnings: Final[str] = (
        "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    )

    command = (
        f"gcc {program_path} {warnings} -O1 -fsanitize=address -g "
        f"-o {os.path.join(compiler_output_directory, output_executable_name)}"
    )
    try:
        result = subprocess.run(
            command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=timeout,
            shell=True,
        )
    except Exception as e:
        logger.error(f"Error running sanitizer compile: {e}")
        return False, str(e)

    logger.debug(f"ASan compile command: {command}")
    logger.debug(f"ASan compile output: {result.stdout + result.stderr}")
    return True


def run_fuzzer(
    executable_name: str,
    codebase_path: str,
    program_path: str,
    executables_afl_path: str,
    fuzzer_compiler_full_path: str,
    fuzzer_full_path: str,
    fuzzer_seed_input_path: str,
    fuzzer_output_path: str,
    timeout_fuzzer,
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
    compile_command = f"{fuzzer_compiler_full_path} {no_stack_protector} {src_path} -o {afl_executable}"
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
    except subprocess.CalledProcessError as e:
        logger.error(f"Fuzzer subprocess failed with return code {e.returncode}.")
        logger.debug(f"Output of fuzzer subprocess: {e.output}")
        return False
    except Exception as e:
        logger.error(f"Error compiling with AFL: {e}")
        return False

    logger.debug(f"Fuzzer compile command: {compile_command}")

    # Prepare the fuzzing command
    if inputFromFile:
        fuzz_command = (
            f"{fuzzer_full_path} -i {fuzzer_seed_input_path} -o {fuzzer_output_path}/{executable_name} "
            f"-t {timeout_fuzzer} {afl_executable} @@"
        )
    else:
        fuzz_command = (
            f"{fuzzer_full_path} -i {fuzzer_seed_input_path} -o {fuzzer_output_path}/{executable_name} "
            f"-t {timeout_fuzzer} {afl_executable}"
        )
    try:
        subprocess.run(
            fuzz_command,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
            shell=True,
            check=True,
        )
    except subprocess.CalledProcessError as e:
        logger.error(f"Fuzzer subprocess failed with return code {e.returncode}.")
        logger.debug(f"Output of fuzzer subprocess: {e.output}")
        return False
    except subprocess.TimeoutExpired:
        # Fuzzer may run indefinitely; timeout is expected.
        logger.info("Fuzzer run timed out as expected.")
        pass
    except Exception as e:
        logger.error(f"Error running fuzzer: {e}")
        return False

    logger.debug(f"Fuzzer run command: {fuzz_command}")

    # # Verify that the fuzzer started by checking for the "fuzzer_stats" file
    if os.path.exists(f"{fuzzer_output_path}/{executable_name}/fuzzer_stats"):
        return True
    return False


def extract_crashes(fuzzer_output_path: str, executable_name: str, inputFromFile: bool):
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


def main():
    config = load_config()

    global logger
    logger = init_logging(config["logging_config"], config["appname"])

    _fuzz_svc_input_codebase_path: Final[str] = config["fuzz_svc_input_codebase_path"]
    _compiled_binary_executables_output_path: Final[str] = config[
        "compiled_binary_executables_output_path"
    ]
    _afl_tool_full_path: Final[str] = config["afl_tool_full_path"]
    _afl_tool_seed_input_path: Final[str] = config["afl_tool_seed_input_path"]
    _afl_tool_compiled_binary_executables_output_path: Final[str] = config[
        "afl_tool_compiled_binary_executables_output_path"
    ]
    _afl_tool_output_path: Final[str] = config["afl_tool_output_path"]
    _afl_compiler_tool_full_path: Final[str] = config["afl_compiler_tool_full_path"]

    logger.info("AppVersion: " + config["version"])
    logger.info("Fuzzer tool name: " + config["fuzzer_tool_name"])
    logger.info("Fuzzer tool version: " + config["fuzzer_tool_version"])

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

        # Step 1: Compile with AddressSanitizer
        logger.info("Entering step 1: compile with ASan")
        source_file_full_path = os.path.join(_fuzz_svc_input_codebase_path, source_file)
        compiled = run_sanitizer(
            source_file_full_path,
            _compiled_binary_executables_output_path,
            executable_name,
        )
        if not compiled:
            logger.error(
                f"ASan compilation failed for {source_file}. Skipping fuzzer run."
            )
            continue
        logger.info(f"ASan compilation succeeded for {source_file}.")

        # Step 2: Run the AFL fuzzer
        logger.info("Entering step 2: run fuzzer")
        logger.info(f"Running fuzzer for {source_file}.")
        fuzzer_started = run_fuzzer(
            executable_name,
            _fuzz_svc_input_codebase_path,
            source_file,
            _afl_tool_compiled_binary_executables_output_path,
            _afl_compiler_tool_full_path,
            _afl_tool_full_path,
            _afl_tool_seed_input_path,
            _afl_tool_output_path,
            timeout,
            inputFromFile,
            isCodebase=True,
        )
        if fuzzer_started:
            logger.info(f"Fuzzer started for {source_file}.")
        else:
            logger.info(f"Fuzzer did not start properly for {source_file}.")

        # Step 3: Extract crash inputs (if any)
        logger.info("Entering step 3: extract crash inputs")
        crashes = extract_crashes(_afl_tool_output_path, executable_name, inputFromFile)
        if crashes:
            logger.info(f"Found {len(crashes)} crash(es) for {source_file}:")
            for crash in crashes:
                logger.info(f"  - {crash}")
        else:
            logger.info(f"No crashes found for {source_file}.")


if __name__ == "__main__":
    main()
