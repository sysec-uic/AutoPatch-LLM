import time
import asyncio
from dataclasses import dataclass
import logging
import os
import subprocess
import sys
from datetime import datetime
from typing import Final, List, Deque
from collections import deque

from cpg_svc_config import CpgSvcConfig

from autopatchpubsub import MessageBrokerClient
from autopatchshared import init_logging, load_config_as_json, get_current_timestamp
from cloudevents.conversion import to_json
from cloudevents.http import CloudEvent
from autopatchdatatypes import CpgScanResult

# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_CPG_SVC_CONFIG: Final[str] = "CPG_SVC_CONFIG"
config: CpgSvcConfig

# before configuration is loaded, use the default logger
logger = logging.getLogger(__name__)


def _remove_joern_scan_temp_file(file_full_path: str) -> None:
    """
    Deletes the specified file if it exists.  Does not yet support NT paths.
    """

    if not os.path.exists(file_full_path):
        logger.info(f"File '{file_full_path}' does not exist, no need to delete.")
        return

    logger.info(f"Attempting to delete {file_full_path}")
    try:
        os.remove(file_full_path)
        logger.info(f"File '{file_full_path}' has been deleted successfully.")
    except FileNotFoundError:
        logger.error(f"File '{file_full_path}' not found.")
    except PermissionError:
        logger.error(f"Permission denied to delete the file '{file_full_path}'.")
    except Exception as e:
        logger.error(f"Error occurred while deleting the file: {e}")


def scan_cpg(
    cpg_scan_tool_full_path: str, c_program_full_path: str
) -> List[CpgScanResult]:

    parsed_datasets: List[CpgScanResult] = []

    joern_scan_temp_log_file_full_path: Final[str] = "/tmp/joern-scan-log.txt"
    _remove_joern_scan_temp_file(joern_scan_temp_log_file_full_path)

    timeout_seconds = 120
    command_name_str: Final[str] = cpg_scan_tool_full_path

    scan_command = [command_name_str]
    # force joern-scan to generate a new cpg
    scan_command.append("--overwrite")

    if not c_program_full_path.endswith(".c"):
        logger.error(f"File {c_program_full_path} is not a C file. Skipping...")
        return []

    cmd = scan_command + [c_program_full_path]
    logger.info(f"Processing {c_program_full_path}...")

    try:
        process = subprocess.Popen(
            cmd,
            stderr=subprocess.PIPE,
            stdout=subprocess.PIPE,
            universal_newlines=True,
            start_new_session=True,  # This creates a new process group
            text=True,
        )
        time.sleep(0.1)  # Give the process a moment to start

        if process.poll() is not None:  # has started correctly
            logger.error(f"Process failed to start. PID: {process.pid}")
            return []

        logger.info(f"Process started with PID: {process.pid}")
        # Wait for process to complete or timeout
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        logger.debug(f"{command_name_str} command output: {stdout} {stderr}")
        logger.info(f"Process completed with PID: {process.pid}")

        output = stdout + stderr

        result_lines = []
        output_lines_set = set(output.splitlines())
        for i in output_lines_set:
            if "Result:" not in i:
                continue
            result_lines.append(i)

        scan_result_list = unmarshall_raw_joern_scan_results(result_lines)
        for i in scan_result_list:
            if not i:
                continue
            parsed_datasets.append(i)

        logger.info(f"Parsed ScanResult: {parsed_datasets}")

    except OSError as e:
        return_code = getattr(e, "returncode", "N/A")
        output = getattr(e, "output", "N/A")
        logger.error(
            f"Failed to start {command_name_str} subprocess. Return Code: {return_code}"
        )
        logger.debug(f"Output of {command_name_str} subprocess: {output}")
    except Exception as e:
        logger.error(f"error processing {c_program_full_path}: {e}")

    return parsed_datasets


async def map_scan_result_as_cloudevent(scan_result: CpgScanResult) -> CloudEvent:
    """
    Maps a ScanResult instance to a CloudEvent Occurence.

    Parameters:
        scan_result (ScanResult): The scan result to be mapped.

    Returns:
        CloudEvent: The corresponding CloudEvent Occurence.
    """
    if scan_result is None or any(
        value is None
        for value in [
            scan_result.executable_name,
            scan_result.vulnerability_severity,
            scan_result.vulnerable_line_number,
            scan_result.vulnerable_function,
            scan_result.vulnerability_description,
        ]
    ):
        logger.error("Invalid scan_result object or one of its values is None.")
        logger.debug(f"scan_result: {scan_result}")
        raise ValueError("Invalid scan_result object or one of its values is None.")

    attributes = {
        "type": "autopatch.scanresult",
        "source": "autopatch.code-property-graph-generator",
        "subject": scan_result.executable_name,
        "time": get_current_timestamp(),
    }

    data = {
        "executable_name": scan_result.executable_name,
        "vulnerability_severity": scan_result.vulnerability_severity,
        "vulnerable_line_number": scan_result.vulnerable_line_number,
        "vulnerable_function": scan_result.vulnerable_function,
        "vulnerability_description": scan_result.vulnerability_description,
    }

    event = CloudEvent(attributes, data)
    return event


async def map_scan_results_as_cloudevents(
    scan_results: List[CpgScanResult],
) -> List[CloudEvent]:
    if len(scan_results) > config.concurrency_threshold:
        # Run in parallel
        tasks = [map_scan_result_as_cloudevent(detail) for detail in scan_results]
        results = await asyncio.gather(*tasks)
    else:
        # Run sequentially
        results = [
            await map_scan_result_as_cloudevent(detail) for detail in scan_results
        ]

    return results


async def produce_output(
    cpg_scan_results: List[CpgScanResult], output_topic: str
) -> None:

    async def produce_event(event: CloudEvent) -> None:
        # flake8 flags the following as F821 because it doesn't recognize the global variable
        logger.debug(f"Producing on Topic: {output_topic}")  # noqa: F821
        logger.debug(f"Producing CloudEvent: {event}")
        message_broker_client.publish(
            output_topic, to_json(event).decode("utf-8")  # noqa: F821
        )

    cpg_scan_results_cloud_events: List[CloudEvent] = (
        await map_scan_results_as_cloudevents(cpg_scan_results)
    )
    message_broker_client: Final[MessageBrokerClient] = MessageBrokerClient(
        config.message_broker_host, config.message_broker_port, logger
    )

    def consume_callback(message: str) -> None:
        logger.info(f"Message received: {message}")

    message_broker_client.consume(output_topic, consume_callback)

    logger.info(f"Producing {len(cpg_scan_results_cloud_events)} CloudEvents.")
    if len(cpg_scan_results_cloud_events) > config.concurrency_threshold:
        # Run in parallel using asyncio.gather
        tasks = [produce_event(event) for event in cpg_scan_results_cloud_events]
        await asyncio.gather(*tasks)
    else:
        # Run sequentially
        for event in cpg_scan_results_cloud_events:
            await produce_event(event)


def load_config(json_config_full_path: str) -> CpgSvcConfig:
    config = load_config_as_json(json_config_full_path, logger)
    return CpgSvcConfig(**config)


def unmarshall_raw_joern_scan_result(scan_result: str) -> CpgScanResult:
    # Parse result into separate attributes and build ScanResult object
    parts = scan_result.split(":")
    # Extract and clean up each part:
    vulnerability_severity = float(parts[1].strip())  # "8.0" converted to float
    vulnerability_description = parts[2].strip()  # "Dangerous function gets() used"
    executable_file_name = parts[3].strip()  # "boflow1.c"
    vulnerable_line_number = int(parts[4].strip())  # "8" converted to int
    vulnerable_function = parts[5].strip()  # "get_input"

    return CpgScanResult(
        vulnerability_severity=vulnerability_severity,
        executable_name=executable_file_name,
        vulnerable_line_number=vulnerable_line_number,
        vulnerable_function=vulnerable_function,
        vulnerability_description=vulnerability_description,
    )


def unmarshall_raw_joern_scan_results(scan_results: List[str]) -> List[CpgScanResult]:
    res: List[CpgScanResult] = []
    for i in scan_results:
        res.append(unmarshall_raw_joern_scan_result(i))
    return res


async def main():
    global config, logger

    config_full_path = os.environ.get(CONST_CPG_SVC_CONFIG)
    if not config_full_path:
        logger.error(
            f"Error: The environment variable {CONST_CPG_SVC_CONFIG} is not set or is empty."
        )
        sys.exit(1)

    config = load_config(config_full_path)
    logger = init_logging(config.logging_config, config.appname)

    CPG_SVC_START_TIMESTAMP: Final[str] = get_current_timestamp()

    logger.info("AppVersion: " + config.version)
    logger.info("AppName: " + config.appname)
    logger.info("Message Broker Host: " + config.message_broker_host)
    logger.info("Message Broker Port: " + str(config.message_broker_port))
    logger.info("Joern Scan Tool Full Path: " + config.scan_tool_full_path)

    # feature 1:
    # Scan a c file using joern-scan and if vulnerability is
    # detected, return a scan results that contain the vulnerability
    # severity, executable name, line number, and function name# c
    input_c_programs: Final[List[str]] = os.listdir(config.cpg_svc_input_codebase_path)

    scan_results_queue: Deque[List[CpgScanResult]] = deque()
    scan_results_as_cloud_events_queue: Deque[List[CloudEvent]] = deque()
    len_input_c_programs = len(input_c_programs)
    for i in range(len_input_c_programs):
        fully_qualified_path = os.path.join(
            config.cpg_svc_input_codebase_path, input_c_programs[i]
        )
        scan_results: List[CpgScanResult] = scan_cpg(
            config.scan_tool_full_path, fully_qualified_path
        )
        if not scan_results:
            logger.info(f"No scan results for {input_c_programs[i]}")
            continue
        scan_results_queue.append(scan_results)

    while scan_results_queue:
        scan_results: List[CpgScanResult] = scan_results_queue.popleft()
        await produce_output(scan_results, config.cpg_svc_scan_result_output_topic)
        logger.info(f"Produced {len(scan_results)} scan results.")

    CPG_SVC_END_TIMESTAMP: Final[str] = get_current_timestamp()
    time_delta = datetime.fromisoformat(CPG_SVC_END_TIMESTAMP) - datetime.fromisoformat(
        CPG_SVC_START_TIMESTAMP
    )
    logger.info(f"Total Processing Time Elapsed: {time_delta}")
    logger.info("Processing complete, exiting.")


if __name__ == "__main__":
    # Run the event loop
    asyncio.run(main())
