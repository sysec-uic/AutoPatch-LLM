import csv
import json
import logging
import logging.config
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Final

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


# run the file with some given input
def run_file(
    executable_path: str,
    executable_name: str,
    crash: str,
    input_from_file: bool,
) -> int:
    # form the command
    if input_from_file:  # The program takes input from file
        # need to put it into a file: figure this out later
        pass
    else:  # The program takes input from stdin
        command = f"echo {crash} | {executable_path}"

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
        logger.info(f"Command run: {command}")
        logger.info(
            f"File {executable_name} ran with input {crash} without any terminating errors."
        )

        return 0
    # if the program terminated with a signal != 0 then this exception is entered
    except subprocess.CalledProcessError as e:
        logger.info(f"Command run: {command}")
        logger.info(
            f"Run of {executable_name} terminated with return code {e.returncode}."
        )
        if e.returncode == 1:
            return 1
        return e.returncode - 128
    except Exception as e:
        logger.error(f"An exception occurred during runtime: {e}")
        return -1


# compiles the program
def compile(file_path: str, file_name: str, executable_path: str) -> str:
    # form the command
    warnings = "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong"
    executable_name = file_name.split(".")[0]
    command = (
        f"gcc {file_path} {warnings} -O1 -g -o {executable_path}/{executable_name}"
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
        logger.info(f"Compiled with command {command}")
    except Exception as e:
        # move this to a log
        logger.error(f"An error occurred while compiling {file_path}: {e}")
    finally:
        # log the command and return either the path to the executable or an empty string on failure
        if os.path.exists(f"{executable_path}/{executable_name}"):
            logger.info(f"Executable {executable_path}/{executable_name} exists.")
            return f"{executable_name}"
        else:
            logger.error(f"Failed to compile {file_path}")
            return ""


def write_crashes_csv(
    crash_detail: str,
    return_code: int,
    csv_path: str,
    inputFromFile: bool,
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
            f.write("timestamp,crash_detail,return_code,inputFromFile\n")

        logger.info(f"Logging crash information in {csv_path}.")
        timestamp = datetime.now().isoformat(timespec="seconds")
        if inputFromFile:
            pass
        else:
            line = f"{timestamp},{crash_detail},{return_code},False\n"
        f.write(line)


def produce_output(
    results_path: str,
    executable_name: str,
    crash_detail: str,
    return_code: int,
    inputFromFile: bool,
) -> None:
    csv_path: Final[str] = os.path.join(
        results_path, f"{executable_name}_full_info.csv"
    )

    write_crashes_csv(crash_detail, return_code, csv_path, inputFromFile)


def log_results(results: dict, results_path: str) -> None:
    log_path = os.path.join(results_path, f"batched_info.txt")
    total_crashes = 0
    total_patched_crashes = 0
    logger.info(f"Creating batched info file {log_path}.")
    with open(log_path, "w") as log:
        for executable_name in results.keys():
            total = results[executable_name]["total_crashes"]
            if total == 0:
                continue
            patched = results[executable_name]["patched_crashes"]
            line = (
                f"Patch for {executable_name} fixed {patched} out of {total} crashes.\n"
            )
            log.write(line)
            success_rate = round(patched / total * 100, 2)
            line = f"Patch is {success_rate}% successful.\n"
            log.write(line)
            total_crashes += total
            total_patched_crashes += patched
        total_success_rate = round(total_patched_crashes / total_crashes * 100, 2)
        line = f"\nTotal success rate of {len(results.keys())} files is {total_patched_crashes} / {total_crashes}, or {total_success_rate}%.\n"


def main():
    global config, logger

    config = load_config()
    logger = init_logging(config["logging_config"], config["appname"])

    _patched_codes_path: Final[str] = config["patched_codes_path"]
    _crashes_events_path: Final[str] = config["crashes_events"]

    EVAL_SVC_START_TIMESTAMP: Final[str] = datetime.now().isoformat(timespec="seconds")
    _patch_eval_results_path: Final[str] = os.path.join(
        config["patch_eval_results"], EVAL_SVC_START_TIMESTAMP
    )
    _executables_path: Final[str] = os.path.join(
        config["executables_path"], EVAL_SVC_START_TIMESTAMP
    )

    logger.info("AppVersion: " + config["version"])
    logger.info("Creating results directory: " + _patch_eval_results_path)
    os.makedirs(_patch_eval_results_path, exist_ok=True)
    logger.info("Creating executables directory: " + _executables_path)
    os.makedirs(_executables_path, exist_ok=True)

    # the folders we need to make:
    # - new executable: the executable directory will already exist
    # - new results: the data directory will already exist

    # proposed flow: 1. compile all the patched codes
    # 2. iterate through each crash that has reference to executable name, track the fails/successes

    executables = list()
    results = dict()
    # iterate through the patched codes directory
    for file_name in os.listdir(_patched_codes_path):
        file_path = os.path.join(_patched_codes_path, file_name)
        # compile the file
        logger.info(f"Compiling: {file_path}")
        executable_name = compile(file_path, file_name, _executables_path)
        # if the compilation was successful, then add the executable path to the list of executables
        # to run
        if executable_name != "":
            executables.append(executable_name)
            results[executable_name] = dict()
            results[executable_name]["total_crashes"] = 0
            results[executable_name]["patched_crashes"] = 0

    # now we need to queue up all the crashes
    # using a list for now just to get the functionality down
    # also assuming for now that the json files are in a local folder

    for crash_file in os.listdir(_crashes_events_path):
        crash_path = os.path.join(_crashes_events_path, crash_file)
        with open(crash_path, "r") as _crash:
            crash = json.load(_crash)
            timestamp = crash["timestamp"]
            executable_name = crash["executable_name"]
            logger.info(f"Processing crash {timestamp} for file {executable_name}.")
            if executable_name not in executables:
                logger.info(
                    f"Skipping crash {timestamp}: executable {executable_name} does not exist in {_executables_path}."
                )
                continue

            crash_detail = bytes.fromhex(crash["crash_detail"])
            executable_path = os.path.join(_executables_path, executable_name)
            return_code = run_file(
                executable_path, executable_name, crash_detail, False
            )
            logger.info(f"Result of running file {executable_name}: {return_code}.")
            logger.info(f"Updating the results csv for {executable_name}")
            produce_output(
                _patch_eval_results_path,
                executable_name,
                crash_detail.hex(),
                return_code,
                False,
            )
            results[executable_name]["total_crashes"] += 1
            if return_code == 0 or return_code == 1:
                results[executable_name]["patched_crashes"] += 1

    log_results(results, _patch_eval_results_path)

    # results files:
    # one per executable detailing which crashes were fixed and which were not
    # one per batch outlining total stats
    # per file format: csv
    # timestamp, crash_detail, return code
    # per batch format:
    # takes the info from each per file one and calculates stats for each file, and for the whole batch

    # tabulate results for each file
    return 0


if __name__ == "__main__":
    main()
