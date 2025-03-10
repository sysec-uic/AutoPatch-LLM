import base64
import json
import logging
import logging.config
import os
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime
from typing import Final
from autopatchdatatypes import CrashDetail

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


def create_temp_crash_file(crash_detail: CrashDetail, temp_dir_path: str) -> str:
    """
    Creates a file with the crash_detail information for passing an executable a path via file.
    """
    os.makedirs(temp_dir_path, exist_ok=True)
    crash_path = os.path.join(temp_dir_path, "crash")

    with open(crash_path, "wb") as crash_file:
        crash_file.write(base64.b64decode(crash_detail.base64_message))
    return crash_path


def run_file(
    executable_path: str,
    executable_name: str,
    crash_detail: CrashDetail,
    temp_crash_file: str = None,
) -> int:
    """
    Run the binary at executable_path with the input given by CrashDetail, either through stdin or via a file.
    """

    # get the crash detail and form the command
    crash = base64.b64decode(crash_detail.base64_message)
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
            timeout=config["run_timeout"],
            shell=True,
        )
        # return 0 on complete success
        logger.debug(f"Command run: {command}")
        logger.debug(f"Command executed with result: {result}")
        logger.debug(
            f"File {executable_name} ran with input {crash} without any terminating errors."
        )
        return 0
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


def compile_file(file_path: str, file_name: str, executable_path: str) -> str:
    """
    Compiles the file at file_path into a binary executable in the executable_path directory.
    """
    # form the command
    warnings = config["compiler_warning_flags"]
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
            timeout=config["compile_timeout"],
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
        if os.path.exists(f"{executable_path}/{executable_name}"):
            logger.info(f"Executable {executable_path}/{executable_name} exists.")
            return f"{executable_name}"
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
        timestamp = datetime.now().isoformat(timespec="seconds")

        line = f"{timestamp},{crash_detail.base64_message},{return_code},{crash_detail.is_input_from_file}\n"
        f.write(line)


def log_crash_information(
    results_path: str, executable_name: str, crash_detail: CrashDetail, return_code: int
) -> None:
    """
    invokes the call to log the crash information for the given executable
    """
    csv_path: Final[str] = os.path.join(results_path, f"{executable_name}.csv")

    write_crashes_csv(crash_detail, return_code, csv_path)


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


def create_crash_detail_objects_for_testing(
    crashes_events_path: str,
) -> list[CrashDetail]:
    """
    This function creates a list of CrashDetail objects from a local directory of json files representing crashes.
    To be deprecated with init of mqtt.
    """
    crash_details = list()
    for crash_file in os.listdir(crashes_events_path):
        crash_path = os.path.join(crashes_events_path, crash_file)
        with open(crash_path, "r") as _crash:
            crash = json.load(_crash)
            executable_name = crash["executable_name"]
            if crash["inputFromFile"] == "False":
                inputFromFile = False
            else:
                inputFromFile = True

            crash_detail_string = bytes.fromhex(crash["crash_detail"]).decode(
                "utf-8", errors="ignore"
            )
            encoded_bytes = base64.b64encode(
                crash_detail_string.encode("utf-8")
            ).decode("utf-8")

            crash_detail = CrashDetail(executable_name, encoded_bytes, inputFromFile)
            logger.debug(f"Created crash detail {crash_detail}")
            crash_details.append(crash_detail)
    return crash_details


def main():
    global config, logger

    # initialize the logger
    config = load_config()
    logger = init_logging(config["logging_config"], config["appname"])

    # get the paths of the patched codes, crash events (to be deprecated), and the temp crashes directory from the config
    _patched_codes_path: Final[str] = config["patched_codes_path"]
    _crashes_events_path: Final[str] = config["crashes_events"]
    _temp_crashes_path: Final[str] = config["temp_crashes_path"]

    # get the current timestamp
    EVAL_SVC_START_TIMESTAMP: Final[str] = datetime.now().isoformat(timespec="seconds")

    # create the timestamped directories
    _patch_eval_results_path: Final[str] = os.path.join(
        config["patch_eval_results"], EVAL_SVC_START_TIMESTAMP
    )
    _executables_path: Final[str] = os.path.join(
        config["executables_path"], EVAL_SVC_START_TIMESTAMP
    )

    # log some info, make the directories if they DNE
    logger.info("AppVersion: " + config["version"])
    logger.info("Creating results directory: " + _patch_eval_results_path)
    os.makedirs(_patch_eval_results_path, exist_ok=True)
    logger.info("Creating executables directory: " + _executables_path)
    os.makedirs(_executables_path, exist_ok=True)
    logger.info("Creating temporary crash files directory: " + _temp_crashes_path)
    os.makedirs(_temp_crashes_path, exist_ok=True)

    # list of files successfully compiled and a dict for the results of each
    executables = list()
    results = dict()
    # iterate through the patched codes directory
    for file_name in os.listdir(_patched_codes_path):
        file_path = os.path.join(_patched_codes_path, file_name)
        # compile the file
        logger.info(f"Compiling: {file_path}")
        executable_name = compile_file(file_path, file_name, _executables_path)
        # if the compilation was successful, then add the executable path to the list of executables to run
        if executable_name != "":
            executables.append(executable_name)
            results[executable_name] = dict()
            results[executable_name]["total_crashes"] = 0
            results[executable_name]["patched_crashes"] = 0

    # discussion point
    logger.info(
        "Converting .json events into CrashDetail objects (development phase only)."
    )
    crash_details = create_crash_detail_objects_for_testing(_crashes_events_path)

    # iterate through each crash (to be deprecated)
    for crash_detail in crash_details:
        logger.info(f"Processing crash {crash_detail}")
        executable_name = crash_detail.executable_name
        # if the crash executable is not in our executables base, then skip it
        if executable_name not in executables:
            logger.info(
                f"Skipping this crash because {executable_name} not in list of compiled executables."
            )
            continue

        # determine if we need to create a temporary crash file, make it if needed
        temp_crash_file = None
        inputFromFile = crash_detail.is_input_from_file
        if inputFromFile:
            temp_crash_file = create_temp_crash_file(crash_detail, _temp_crashes_path)

        # run the file
        executable_path = os.path.join(_executables_path, executable_name)
        return_code = run_file(
            executable_path,
            executable_name,
            crash_detail,
            temp_crash_file,
        )

        # log the crash information to that executables dedicated csv file
        logger.info(f"Result of running file {executable_name}: {return_code}.")
        logger.info(f"Updating the results csv for {executable_name}")
        log_crash_information(
            _patch_eval_results_path,
            executable_name,
            crash_detail,
            return_code,
        )

        # update the results dict for that executable with the result of the run
        results[executable_name]["total_crashes"] += 1
        if return_code == 0 or return_code == 1:
            results[executable_name]["patched_crashes"] += 1
    # log the batched results
    log_results(results, _patch_eval_results_path)

    return 0


if __name__ == "__main__":
    main()
