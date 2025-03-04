import asyncio
import base64
import json
import logging
import logging.config
import os
import signal
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Final, List

import paho.mqtt.client as mqtt_client
import paho.mqtt.enums as mqtt_enums
from autopatchdatatypes import CrashDetail
from cloudevents.http import CloudEvent


# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_FUZZ_SVC_CONFIG: Final[str] = "FUZZ_SVC_CONFIG"

config = dict()
logger = logging.getLogger(__name__)


@dataclass
class Config:
    version: str
    appname: str
    logging_config: str
    concurrency_threshold: int
    message_broker_host: str
    message_broker_port: int
    message_broker_protocol: str
    fuzz_svc_output_topic: str
    fuzz_svc_input_codebase_path: str
    fuzz_svc_output_path: str
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
    message_broker_ca_certs: str
    message_broker_certfile: str
    message_broker_keyfile: str


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


async def MapCrashDetailAsCloudEvent(crash_detail: CrashDetail) -> CloudEvent:
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
        logger.debug("CrashDetail: %s", crash_detail)
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


def get_current_timestamp() -> str:
    """
    Get the current timestamp in ISO 8601 format.
    """
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )


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
    warn_flags = config["compiler_warning_flags"]
    feature_flags = config["compiler_feature_flags"]
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
        f"{fuzzer_full_path} -m {config['afl_tool_child_process_memory_limit_mb']} -i {fuzzer_seed_input_path} -o {fuzzer_output_path}/{program_name} "
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

        # Check if process started successfully
        if process.poll() is not None:
            logger.error("Fuzzer subprocess failed to start.")
        else:
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
    crash_dir = os.path.join(f"{fuzzer_output_path}", f"{executable_name}", "crashes")
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


async def MapCrashDetailsAsCloudEvents(
    crash_details: List[CrashDetail],
) -> List[CloudEvent]:
    if len(crash_details) > config["concurrency_threshold"]:
        # Run in parallel
        tasks = [MapCrashDetailAsCloudEvent(detail) for detail in crash_details]
        results = await asyncio.gather(*tasks)
    else:
        # Run sequentially
        results = [await MapCrashDetailAsCloudEvent(detail) for detail in crash_details]

    return results


class MessageBrokerClient:
    def __init__(self):
        _client = self.connect_message_broker()
        self.client = _client
        self.client.enable_logger(logger)
        self.FIRST_RECONNECT_DELAY = 1
        self.RECONNECT_RATE = 2
        self.MAX_RECONNECT_COUNT = 12
        self.MAX_RECONNECT_DELAY = 60

    def connect_message_broker(self) -> mqtt_client.Client:
        def on_connect(client, userdata, flags, rc):
            if rc == 0:
                logger.info("Connected to MQTT Broker!")
            else:
                logger.error("Failed to connect to MQTT Broker!")
                logger.debug(f"Failed to connect, return code {rc}\n")

        def on_disconnect(self, client, userdata, rc):
            logger.info(f"Disconnected with result code: {rc}")
            reconnect_count, reconnect_delay = 0, self.FIRST_RECONNECT_DELAY
            while reconnect_count < self.MAX_RECONNECT_COUNT:
                logger.info(f"Reconnecting in {reconnect_delay} seconds...")
                time.sleep(reconnect_delay)

                try:
                    client.reconnect()
                    logger.info("Reconnected successfully!")
                    return
                except Exception as err:
                    logging.error(f"{err}. Reconnect failed. Retrying...")

                reconnect_delay *= self.RECONNECT_RATE
                reconnect_delay = min(reconnect_delay, self.MAX_RECONNECT_DELAY)
                reconnect_count += 1
            logger.info(
                f"Reconnect failed after {reconnect_count} attempts. Exiting..."
            )

        def on_publish(client, userdata, mid):
            logger.info(f"Message {mid} published")

        def generate_uuid():
            return str(uuid.uuid4())

        # Generate a Client ID with the publish prefix.
        client_id = f"publish-{generate_uuid()}"
        client = mqtt_client.Client(
            client_id=client_id,
            callback_api_version=mqtt_enums.CallbackAPIVersion.VERSION2,
        )
        # client.username_pw_set(username, password)
        # client.tls_set(
        #     ca_certs=config["message_broker_ca_certs"], certfile=config["message_broker_certfile"], keyfile=config["message_broker_keyfile"]
        # )
        client.on_connect = on_connect
        client.on_disconnect = on_disconnect
        client.on_publish = on_publish
        logger.info(
            "Connecting to MQTT Broker on {}:{}".format(
                config["message_broker_host"], config["message_broker_port"]
            )
        )
        client.connect(config["message_broker_host"], config["message_broker_port"])
        return client

    def publish(self, topic: str, message: str) -> None:
        """
        Publish a message to the specified topic.
        """
        # at least once delivery, publish is non-blocking by default
        result: mqtt_client.MQTTMessageInfo = self.client.publish(topic, message, qos=1)
        logger.info(f"Published message to topic {topic}")
        if result.rc != mqtt_enums.MQTTErrorCode.MQTT_ERR_SUCCESS:
            logger.error(f"Failed to send message to topic {topic}")
            return


async def produce_output(crash_details: List[CrashDetail]) -> None:

    async def produce_event(event: CloudEvent) -> None:
        logger.debug(f"Producing on Topic: {config['fuzz_svc_output_topic']}")
        logger.debug(f"Producing CloudEvent: {event}")
        message_broker_producer.publish(config["fuzz_svc_output_topic"], str(event))

    crash_details_cloud_events: List[CloudEvent] = await MapCrashDetailsAsCloudEvents(
        crash_details
    )
    message_broker_producer: Final[MessageBrokerClient] = MessageBrokerClient()

    logger.info(f"Producing {len(crash_details_cloud_events)} CloudEvents.")
    if len(crash_details_cloud_events) > config["concurrency_threshold"]:
        # Run in parallel using asyncio.gather
        tasks = [produce_event(event) for event in crash_details_cloud_events]
        await asyncio.gather(*tasks)
    else:
        # Run sequentially
        for event in crash_details_cloud_events:
            await produce_event(event)

    csv_path: Final[str] = os.path.join(config["fuzz_svc_output_path"], "crashes.csv")
    write_crashes_csv(crash_details, csv_path)


async def main():
    global config, logger

    config = load_config()
    logger = init_logging(config["logging_config"], config["appname"])

    FUZZ_SVC_START_TIMESTAMP: Final[str] = get_current_timestamp()

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
            config["iconv_tool_timeout"],
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
