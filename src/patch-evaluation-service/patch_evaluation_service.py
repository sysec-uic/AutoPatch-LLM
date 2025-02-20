import json
import logging
import logging.config
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from typing import Final

EXECUTABLES_PATH = os.environ.get(
    "EXECUTABLES_PATH", "workspace/AutoPatch-LLM/src/executables/"
)

PATCHED_CODES_PATH = os.environ.get(
    "PATCHED_CODES_PATH", "workspace/AutoPatch-LLM/src/patched_codes/"
)

EVAL_COMMAND_LOG_PATH = os.environ.get(
    "EVAL_COMMAND_LOG_PATH",
    "/workspace/AutoPatch-LLM/src/evaluation_service/command_log/",
)
OUTPUT_PATH = os.environ.get("OUTPUT_PATH", "/workspace/AutoPatch-LLM/src/output_")

RESULTS_PATH = os.environ.get(
    "RESULTS_PATH", "/workspace/AutoPatch-LLM/src/evaluation_service/results/"
)

COMPILE_TIMEOUT = 10
RUN_TIMEOUT = 10

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_PATCH_EVAL_SVC_CONFIG: Final[str] = "PATCH_EVAL_SVC_CONFIG"

config = dict()
logger = logging.getLogger(__name__)


@dataclass
class Config:
    version: str
    appname: str
    logging_config: str
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
    config_path = os.environ.get(CONST_PATCH_EVAL_SVC_CONFIG)
    if not config_path:
        logger.error(
            "Error: The environment variable 'CONST_PATCH_EVAL_SVC_CONFIG' is not set or is empty."
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


# logs the given command in the command_log file for this code
def log_command(command: str, command_type: str, file_name: str):
    if command_type == "COMPILE":
        with open(f"{EVAL_COMMAND_LOG_PATH}{file_name}.txt", "w") as log_file:
            log_file.write("COMPILE COMMAND:\n")
            log_file.write(command + "\n")
    elif command_type == "RUN":
        with open(f"{EVAL_COMMAND_LOG_PATH}{file_name}.txt", "a") as log_file:
            log_file.write("RUN COMMAND:\n")
            log_file.write(command + "\n")


# logs the overall results of the evaluation
def log_results(executable_path: str, file_name: str, results: list):
    log_path = RESULTS_PATH + file_name.split(".")[0] + ".txt"

    # count the number of patched as those whose status code was 0 or 1
    # this might need further consideration
    num_patched = len([crash for crash in results if crash[2] == 0 or crash[2] == 1])

    # column names with file, the signal of the original code, the patch signal result, and the outcome
    columns = ["input_name", "source_signal", "patch_signal", "outcome"]

    # get the max width of the column data
    col_widths = [
        max(len(str(item)) for item in column) for column in zip(*results, columns)
    ]

    # open a file to write the log
    with open(f"{log_path}", "w") as log_file:
        # write header
        log_file.write(f"RESULTS for {executable_path}:\n\n")
        header = " | ".join(
            f"{col.ljust(width)}" for col, width in zip(columns, col_widths)
        )
        log_file.write(header + "\n")
        log_file.write("-" * len(header) + "\n")

        # write data rows
        for row in results:
            row_line = " | ".join(
                f"{str(cell).ljust(width)}" for cell, width in zip(row, col_widths)
            )
            log_file.write(row_line + "\n")
        # write overall patch success
        log_file.write(
            f"\nNumber of patched crashes: {num_patched} out of {len(results)} original crashes."
        )


# compiles the program
def compile(file_path: str, file_name: str) -> str:
    # form the command
    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    executable_name = file_name.split(".")[0]
    command = (
        f"gcc {file_path} {warnings} -O1 -g -o {EXECUTABLES_PATH}{executable_name}"
    )

    # run the command
    try:
        result = subprocess.run(
            [command],
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=COMPILE_TIMEOUT,
            shell=True,
        )
    except Exception as e:
        # move this to a log
        print(f"Error during compilation: {e}")
    finally:
        # log the command and return either the path to the executable or an empty string on failure
        log_command(command, "COMPILE", executable_name)
        if os.path.exists(f"{EXECUTABLES_PATH}{executable_name}"):
            return f"{EXECUTABLES_PATH}{executable_name}"
        else:
            return ""


# run the file with some given input
def run_file(
    executable_path: str,
    executable_name: str,
    crash_path: str,
    crash: str,
    input_from_file: bool,
) -> int:
    # form the command
    if input_from_file:  # The program takes input from file
        command = f"{executable_path} {crash_path}{crash}"
    else:  # The program takes input from stdin
        command = f"cat {crash_path}{crash} | {executable_path}"

    # run the command
    try:
        result = subprocess.run(
            [command],
            check=True,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            timeout=RUN_TIMEOUT,
            shell=True,
        )
        # return 0 on complete success
        return 0
    # if the program terminated with a signal != 0 then this exception is entered
    except subprocess.CalledProcessError as e:
        if e.returncode == 1:
            return 1
        return e.returncode - 128
    except Exception as e:
        print(f"Error during run: {e}")
        return -1
    # log the command
    finally:
        log_command(command, "RUN", executable_name)


# run a file with a batch of crashes
def run_crashes(executable_path: str, file_name: str) -> list:
    # the list to store the results
    results = list()
    executable_name = file_name.split(".")[0]
    # input from file needs to be updated eventually
    input_from_file = False

    # iterate through the crashes
    crash_path = OUTPUT_PATH + executable_name + "/crashes/"
    for input_file in os.listdir(crash_path):
        # skip the README that is created by the fuzzer
        if input_file == "README.txt":
            continue

        # extract the signal produced by running the original source code with this input
        # (the signal is in the name of the input file)
        signal_pattern = r"sig:(\d+)"
        match = re.search(signal_pattern, input_file)
        if match:
            source_sig_value = match.group(1)

        # run the patch with the input, the return value is the signal
        patch_sig_value = run_file(
            executable_path, executable_name, crash_path, input_file, input_from_file
        )
        # if the new signal is 0 or 1, then success (might change)
        # add the outcome to the results log
        if patch_sig_value == 0 or patch_sig_value == 1:
            results.append((input_file, source_sig_value, patch_sig_value, "success"))
        # otherwise, failure
        else:
            results.append((input_file, source_sig_value, patch_sig_value, "failure"))
    # return the results
    return results


def main():
    global config, logger

    config = load_config()
    logger = init_logging(config["logging_config"], config["appname"])

    # make the directories for the executable, the command log, and the results
    os.makedirs(EXECUTABLES_PATH, exist_ok=True)
    os.makedirs(EVAL_COMMAND_LOG_PATH, exist_ok=True)
    os.makedirs(RESULTS_PATH, exist_ok=True)

    # iterate through the patched codes directory
    for file_name in os.listdir(PATCHED_CODES_PATH):
        file_path = os.path.join(PATCHED_CODES_PATH, file_name)
        # compile the file
        executable_path = compile(file_path, file_name)
        # if the executable was successfully made
        if executable_path != "":
            # run the executable with the crashes and log the results
            results = run_crashes(executable_path, file_name)
            log_results(executable_path, file_name, results)
    return 0


if __name__ == "__main__":
    main()
