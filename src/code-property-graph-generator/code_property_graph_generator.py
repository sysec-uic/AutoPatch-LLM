import time
import asyncio
import base64
from dataclasses import dataclass, field
import glob
import logging
import logging.config
import os
import pandas as pd
import signal
import subprocess
import sys
from datetime import datetime
from typing import Final, List, Dict

# from autopatchdatatypes import CpgDetail
from autopatchpubsub import MessageBrokerClient
from autopatchshared import init_logging, load_config_as_json, get_current_timestamp
from cloudevents.http import CloudEvent


@dataclass
class CpgDetail:
    # vuln (vulnerable) - boolean flag indicating whether a CVE has been detected in this cpg
    is_vuln: bool
    # vuln_type - classification of detected vulnerability
    vuln_type: str
    graph: dict = field(default_factory=dict)


@dataclass
class ScanResult:
    vuln_severity: float
    executable_name: str
    vuln_line: int
    vuln_function: str
    vuln_description: str


@dataclass
class CpgSvcConfig:
    version: str
    appname: str
    logging_config: str
    message_broker_host: str
    message_broker_port: int
    message_broker_protocol: str
    concurrency_threshold: int
    cpg_svc_output_topic: str
    cpg_svc_input_codebase_path: str
    cpg_svc_output_path: str


# this is the name of the environment variable that will be used point to the configuration map file to load
CONST_CPG_SVC_CONFIG: Final[str] = "CPG_SVC_CONFIG"
config: CpgSvcConfig

# before configuration is loaded, use the default logger
logger = logging.getLogger(__name__)


async def map_cpg_detail_as_cloudevent(cpg_detail: CpgDetail) -> CloudEvent:
    """
    Maps a CpgDetail instance to a CloudEvent Occurence.

    Parameters:
        crash (CpgDetail): The crash detail to be mapped.

    Returns:
        CloudEvent: The corresponding CloudEvent Occurence.
    """
    if cpg_detail is None or any(
        value is None
        for value in [
            cpg_detail.executable_name,
        ]
    ):
        logger.error("Invalid cpg_detail object or one of its values is None.")
        logger.debug(f"cpgDetail: {cpg_detail}")
        raise ValueError("Invalid cpg_detail object or one of its values is None.")

    attributes = {
        "type": "autopatch.cpgdetail",
        "source": "autopatch.code-property-graph-generator",
        "subject": cpg_detail.executable_name,
        "time": get_current_timestamp(),
    }

    data = {
        "executable_name": cpg_detail.executable_name,
    }

    # event = CloudEvent(attributes, data)
    # return event
    raise NotImplementedError


def extract_code_property_graph(code_path: str) -> list[str]:
    timeout_seconds = 10
    command_name_str: Final[str] = "joern-parse"
    parse_command = ["joern-parse"]
    cpg_list: List[str] = []

    c_programs_in_code_path = os.listdir(code_path)

    for filename in c_programs_in_code_path:
        filepath = os.path.join(code_path, filename)
        basename, ext = os.path.splitext(filename)
        # TODO change to asset data directory
        output_filename = os.path.join(code_path, basename + ".cpg")
        cmd = parse_command + [filepath, "-o", output_filename]

        if os.path.isfile(filepath):
            logger.info(f"Processing {filename}...")
            try:
                process = subprocess.Popen(
                    cmd,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    universal_newlines=True,
                    start_new_session=True,  # This creates a new process group
                    text=True,
                )
                time.sleep(0.5)  # Give the process a moment to start

                if process.poll() is None:  # has started correctly
                    logger.info(f"Process started with PID: {process.pid}")
                    # Wait for process to complete or timeout
                    stdout, stderr = process.communicate(timeout=timeout_seconds)
                    logger.debug(
                        f"{command_name_str} command output: {stdout} {stderr}"
                    )
                    logger.info(f"Process completed with PID: {process.pid}")
                else:
                    logger.error(f"Process failed to start. PID: {process.pid}")

                cpg_list.append(output_filename)
                logger.info(
                    f"Successfuly wrote code-property-graph to: {output_filename}"
                )

            except OSError as e:
                return_code = getattr(e, "returncode", "N/A")
                output = getattr(e, "output", "N/A")
                logger.error(
                    f"Failed to start {command_name_str} subprocess. Return Code: {return_code}"
                )
                logger.debug(f"Output of {command_name_str} subprocess: {output}")
            except Exception as e:
                logger.error(
                    f"Unhandled novel Exception error processing {filename}: {e}"
                )

    return cpg_list


def write_code_property_graphs_as_csv(cpg_path: str) -> List[str]:
    timeout_seconds = 10
    command_name_str: Final[str] = "joern-export"
    out_cmd_line_arg: Final[str] = "--out"
    representation_cmd_line_arg: Final[str] = "--repr"
    format_cmd_line_arg: Final[str] = "--format"
    neo4jcsv_cmd_line_arg: Final[str] = "neo4jcsv"
    all_cmd_line_arg: Final[str] = "all"

    csv_gen_command = [command_name_str]
    cpg_csv_folders = []
    files_in_cpg_path = os.listdir(cpg_path)
    for filename in files_in_cpg_path:
        logger.info(f"Processing {filename}...")
        filepath = os.path.join(cpg_path, filename)
        basename, ext = os.path.splitext(filename)

        # TODO change path to service data directory
        output_dir = cpg_path + basename + os.sep
        cmd: Final[str] = csv_gen_command + [
            filepath,
            out_cmd_line_arg,
            output_dir,
            representation_cmd_line_arg,
            all_cmd_line_arg,
            format_cmd_line_arg,
            neo4jcsv_cmd_line_arg,
        ]

        if os.path.isfile(filepath):
            try:
                process = subprocess.Popen(
                    cmd,
                    stderr=subprocess.PIPE,
                    stdout=subprocess.PIPE,
                    universal_newlines=True,
                    start_new_session=True,  # This creates a new process group
                    text=True,
                )
                time.sleep(0.5)  # Give the process a moment to start

                # Wait here
                if process.poll() is None:  # has started correctly
                    logger.info(f"Process started with PID: {process.pid}")
                    # Wait for process to complete or timeout
                    stdout, stderr = process.communicate(timeout=timeout_seconds)
                    logger.debug(
                        f"{command_name_str} command output: {stdout} {stderr}"
                    )
                    logger.info(f"Process completed with PID: {process.pid}")
                else:
                    logger.error(f"Process failed to start. PID: {process.pid}")

                cpg_csv_folders.append(output_dir)

                logger.info(f"Successfuly wrote code-property-graph to: {output_dir}")
            except OSError as e:
                return_code = getattr(e, "returncode", "N/A")
                output = getattr(e, "output", "N/A")
                logger.error(
                    f"Failed to start {command_name_str} subprocess. Return Code: {return_code}"
                )
                logger.debug(f"Output of {command_name_str} subprocess: {output}")
            except Exception as e:
                logger.error(f"error processing {filename}: {e}")

    return cpg_csv_folders


def consolidate_csv(pattern: str) -> List[pd.DataFrame]:
    data_suffix = "_data.csv"
    header_suffix = "_header.csv"
    files = glob.glob(pattern)
    dfs = []
    for file in files:
        logger.info(f"Processing file: {file}")
        # Derive header filename: replace the data_suffix with header_suffix
        header_file = file.replace(data_suffix, header_suffix)
        if os.path.exists(header_file):
            # use header.csv to name columns
            with open(header_file, "r") as hf:
                header_line = hf.readline().strip()
                columns = header_line.split(",")
            df = pd.read_csv(file, header=None, names=columns)
            dfs.append(df)
        else:
            # TODO handle this differently
            logger.error(f"Header file {header_file} not found for data file {file}.")
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    else:
        # Handle this differently? Only get here if no dfs created
        return pd.DataFrame()


def process_cpg_folders(csv_path: str) -> dict:
    cpg_df = {}
    for folder in os.listdir(csv_path):
        # ignore joern folder 'workspace'
        if folder == "workspace":
            continue
        logger.info(f"Processing folder: {folder}")
        folder_path = os.path.join(csv_path, folder)
        if os.path.isdir(folder_path):
            # Build glob patterns for node and edge data files
            nodes_pattern = os.path.join(folder_path, "nodes_*_data.csv")
            edges_pattern = os.path.join(folder_path, "edges_*_data.csv")

            nodes_df = consolidate_csv(nodes_pattern)
            edges_df = consolidate_csv(edges_pattern)

            cpg_df[folder] = {"nodes": nodes_df, "edges": edges_df}
    return cpg_df


def _remove_jeorn_scan_temp_file(file_full_path: str) -> None:
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


def scan_cpg(c_program_full_path: str) -> Dict:

    results: Dict[str, str] = {}

    joern_scan_temp_log_file_full_path: Final[str] = "/tmp/joern-scan-log.txt"
    _remove_jeorn_scan_temp_file(joern_scan_temp_log_file_full_path)

    timeout_seconds = 20
    command_name_str: Final[str] = "joern-scan"

    scan_command = [command_name_str]
    # force joern-scan to generate a new cpg
    scan_command.append("--overwrite")

    if not c_program_full_path.endswith(".c"):
        logger.error(f"File {c_program_full_path} is not a C file. Skipping...")
        return None

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
            return None

        logger.info(f"Process started with PID: {process.pid}")
        # Wait for process to complete or timeout
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        logger.debug(f"{command_name_str} command output: {stdout} {stderr}")
        logger.info(f"Process completed with PID: {process.pid}")

        output = stdout + stderr

        reversed_output = output.splitlines()[::-1]
        for line in reversed_output:
            if line.startswith("Result:"):
                results[c_program_full_path] = line

        logger.info(
            f"Finished scanning {c_program_full_path} with result: {results[c_program_full_path]}"
        )
    except OSError as e:
        return_code = getattr(e, "returncode", "N/A")
        output = getattr(e, "output", "N/A")
        logger.error(
            f"Failed to start {command_name_str} subprocess. Return Code: {return_code}"
        )
        logger.debug(f"Output of {command_name_str} subprocess: {output}")
    except Exception as e:
        logger.error(f"error processing {c_program_full_path}: {e}")
    return results


async def map_cpgdetail_as_cloudevents(
    crash_details: List[CpgDetail],
) -> List[CloudEvent]:
    if len(crash_details) > config.concurrency_threshold:
        # Run in parallel
        tasks = [map_cpg_detail_as_cloudevent(detail) for detail in crash_details]
        results = await asyncio.gather(*tasks)
    else:
        # Run sequentially
        results = [
            await map_cpg_detail_as_cloudevent(detail) for detail in crash_details
        ]

    return results


async def produce_output(cpg_details: List[CpgDetail]) -> None:

    async def produce_event(event: CloudEvent) -> None:
        # flake8 flags the following as F821 because it doesn't recognize the global variable
        logger.debug(f"Producing on Topic: {config.cpg_svc_output_topic}")  # noqa: F821
        logger.debug(f"Producing CloudEvent: {event}")
        message_broker_client.publish(
            config.cpg_svc_output_topic, str(event)  # noqa: F821
        )

    cpg_details_cloud_events: List[CloudEvent] = await map_crashdetails_as_cloudevents(
        cpg_details
    )
    message_broker_client: Final[MessageBrokerClient] = MessageBrokerClient(
        config.message_broker_host, config.message_broker_port, logger
    )

    logger.info(f"Producing {len(cpg_details_cloud_events)} CloudEvents.")
    if len(cpg_details_cloud_events) > config.concurrency_threshold:
        # Run in parallel using asyncio.gather
        tasks = [produce_event(event) for event in cpg_details_cloud_events]
        await asyncio.gather(*tasks)
    else:
        # Run sequentially
        for event in cpg_details_cloud_events:
            await produce_event(event)

    csv_path: Final[str] = os.path.join(
        config.cpg_svc_output_path, "code-property-graphs.csv"
    )
    write_code_property_graphs_as_csv(cpg_details, csv_path)


def load_config(json_config_full_path: str) -> CpgSvcConfig:
    config = load_config_as_json(json_config_full_path, logger)
    return CpgSvcConfig(**config)


def unmarshall_raw_joern_scan_result(
    executable_name: str, scan_result: str
) -> ScanResult:
    raise NotImplementedError()


def unmarshall_raw_joern_scan_results(scan_results: Dict[str, str]) -> List[ScanResult]:
    res = [unmarshall_raw_joern_scan_result(k, v) for k, v in scan_results.items()]
    return res


def work_in_progress_features() -> None:
    # feature 2:
    # Generate a code property graph (CPG) for each c file in the input directory
    # saved as a .cpg file compatible with joern
    cpg_list = extract_code_property_graph(config.cpg_svc_input_codebase_path)
    logger.info(cpg_list)

    # feature 3:
    # Export the code property graphs (CPGs) in input directory as CSV files
    # compatible with Neo4j and networkx
    csv_list = write_code_property_graphs_as_csv(config.cpg_svc_output_path)
    logger.info(csv_list)

    # feature 4:
    # Consolidate the CSV files into one dataframe containing nodes and edges
    cpg_df = process_cpg_folders(
        "/workspace/AutoPatch-LLM/src/code-property-graph-generator/data/dev"
    )
    logger.info(cpg_df.keys())


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
    # TODO Update the config names and values
    # logger.info("CPG tool name: " + config.fuzzer_tool_name)
    # logger.info("CPG tool version: " + config.fuzzer_tool_version)

    # feature 1:
    # Scan a c file using joern-scan and if vulnerability is
    # detected, return a scan results that contain the vulnerability
    # severity, executable name, line number, and function name# c
    input_c_programs: Final[List[str]] = os.listdir(config.cpg_svc_input_codebase_path)

    raw_joern_scan_results: Dict[str, str] = {}

    len_input_c_programs = len(input_c_programs)
    for i in range(len_input_c_programs):
        fully_qualified_path = os.path.join(
            config.cpg_svc_input_codebase_path, input_c_programs[i]
        )
        res = scan_cpg(fully_qualified_path)
        logger.info(f"Scan result for {input_c_programs[i]}: {res}")
        raw_joern_scan_results[input_c_programs[i]] = res

    # raw_joern_scan_results = scan_cpg(input_c_programs)
    logger.info(raw_joern_scan_results)

    # TODO convert from raw str to strong type
    # scan_results: List[ScanResult] = [unmarshaell_raw_joern_scan_results(x) for x in raw_joern_scan_results]
    # logger.info(scan_results)

    # TODO
    # work_in_progress_features()

    CPG_SVC_END_TIMESTAMP: Final[str] = get_current_timestamp()
    time_delta = datetime.fromisoformat(CPG_SVC_END_TIMESTAMP) - datetime.fromisoformat(
        CPG_SVC_START_TIMESTAMP
    )
    logger.info(f"Total Processing Time Elapsed: {time_delta}")
    logger.info("Processing complete, exiting.")


if __name__ == "__main__":
    # Run the event loop
    asyncio.run(main())
