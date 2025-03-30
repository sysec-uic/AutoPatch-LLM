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
from typing import Final, List

# from autopatchdatatypes import CpgDetail
from autopatchpubsub import MessageBrokerClient
from autopatchshared import init_logging, load_config_as_json, get_current_timestamp
from cloudevents.http import CloudEvent


@dataclass
class CpgDetail:
    # vuln (vulnerable) - boolean flag indicating whether a CVE has been detected in this cpg
    vuln: bool
    # vuln_type - classification of detected vulnerability
    vuln_type: str
    graph: dict = field(default_factory=dict)


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


def extract_code_property_graph(
    crash_details: List[CpgDetail], code_path: str
) -> list[str]:
    parse_command = ["joern-parse"]
    cpg_list = []

    for filename in os.listdir(code_path):
        filepath = os.path.join(code_path, filename)
        basename, ext = os.path.splitext(filename)
        # TODO change to asset data directory
        output_filename = os.path.join(code_path, basename + ".cpg")
        cmd = parse_command + [filepath, "-o", output_filename]

        if os.path.isfile(filepath):
            try:
                process = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )

                cpg_list.append(output_filename)
            except Exception as e:
                print(f"error processing {filename}: {e}")

    return cpg_list


def write_code_property_graphs_as_csv(
    crash_details: List[CpgDetail], cpg_path: str
) -> list[str]:
    csv_gen_command = ["joern-export"]
    cpg_list = []
    for filename in os.listdir(cpg_path):
        filepath = os.path.join(cpg_path, filename)
        basename, ext = os.path.splitext(filename)

        # TODO change path to service data directory
        output_dir = cpg_path + basename + os.sep
        cmd = csv_gen_command + [
            filepath,
            "--out",
            output_dir,
            "--repr",
            "all",
            "--format",
            "neo4jcsv",
        ]

        if os.path.isfile(filepath):
            try:
                process = subprocess.run(
                    cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
                )
                cpg_list.append(output_dir)

            except Exception as e:
                print(f"error processing {filename}: {e}")

    return cpg_list


def consolidate_csv(crash_details: List[CpgDetail], pattern: str) -> list[pd.DataFrame]:
    data_suffix = "_data.csv"
    header_suffix = "_header.csv"
    files = glob.glob(pattern)
    dfs = []
    for file in files:
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
            print(f"Header file {header_file} not found for data file {file}.")
    if dfs:
        return pd.concat(dfs, ignore_index=True)
    else:
        # Handle this differently? Only get here if no dfs created
        return pd.DataFrame()


def process_cpg_folders(crash_details: List[CpgDetail], csv_path: str) -> dict:
    cpg_df = {}
    for folder in os.listdir(csv_path):
        # ignore joern folder 'workspace'
        if folder == "workspace":
            continue
        folder_path = os.path.join(csv_path, folder)
        if os.path.isdir(folder_path):
            # Build glob patterns for node and edge data files
            nodes_pattern = os.path.join(folder_path, "nodes_*_data.csv")
            edges_pattern = os.path.join(folder_path, "edges_*_data.csv")

            nodes_df = consolidate_csv(nodes_pattern)
            edges_df = consolidate_csv(edges_pattern)

            cpg_df[folder] = {"nodes": nodes_df, "edges": edges_df}
    return cpg_df


# TODO: change return to data object
def scan_cpg(code_path: str) -> dict:
    results = {}
    scan_command = ["joern-scan"]
    # force joern-scan to generate a new cpg
    scan_command.append("--overwrite")

    for filename in os.listdir(code_path):
        filepath = os.path.join(code_path, filename)

        if os.path.isfile(filepath):

            try:
                process = subprocess.run(
                    scan_command + [filepath],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )

                output = process.stdout + process.stderr
                result_line = None
                for line in output.splitlines():
                    if line.startswith("Result:"):
                        if result_line != None:  # lookout for multiple 'result_line's
                            print("more than one result found!")
                            print(f"result_line = {result_line}")
                            print(f"line = {line}")
                        else:
                            result_line = line

                results[filename] = result_line

            except Exception as e:
                print(f"error processing {filename}: {e}")
                # Change behavior to list where result = error?
                results[filename] = {"result": None, "error": str(e)}
    return results


async def map_crashdetails_as_cloudevents(
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

    # TODO delete the fuzzing config implementation below and replace with CPG specific context

    # _fuzz_svc_input_codebase_path: Final[str] = config.fuzz_svc_input_codebase_path
    # _fuzzer_tool_timeout_seconds: Final[int] = config.fuzzer_tool_timeout_seconds
    # _afl_tool_full_path: Final[str] = config.afl_tool_full_path
    # _afl_tool_seed_input_path: Final[str] = config.afl_tool_seed_input_path
    # _afl_tool_compiled_binary_executables_output_path: Final[str] = (
    #     config.afl_tool_compiled_binary_executables_output_path
    # )
    # _afl_tool_output_path: Final[str] = os.path.join(
    #     config.afl_tool_output_path, CPG_SVC_START_TIMESTAMP
    # )
    # _afl_compiler_tool_full_path: Final[str] = config.afl_compiler_tool_full_path

    logger.info("AppVersion: " + config.version)
    # TODO Update the config names and values
    # logger.info("CPG tool name: " + config.fuzzer_tool_name)
    # logger.info("CPG tool version: " + config.fuzzer_tool_version)

    # TODO
    # do the thing
    scan_results = scan_cpg(config.cpg_svc_input_codebase_path)
    print(scan_results)

    cpg_list = extract_code_property_graph(config.cpg_svc_input_codebase_path)
    print(cpg_list)
    # TODO adjust to handle timestamped directory
    # write_code_property_graphs_as_csv() looks for .cpg files in passed directory
    # process_cpg_folders() looks for subdirectories in passed directory
    # therefore it should be ok to use same timestamped directory
    csv_list = write_code_property_graphs_as_csv(config.cpg_svc_output_path)
    print(csv_list)
    cpg_df = process_cpg_folders(config.cpg_svc_output_path)
    print(cpg_df)

    CPG_SVC_END_TIMESTAMP: Final[str] = get_current_timestamp()
    time_delta = datetime.fromisoformat(CPG_SVC_END_TIMESTAMP) - datetime.fromisoformat(
        CPG_SVC_START_TIMESTAMP
    )
    logger.info(f"Total Processing Time Elapsed: {time_delta}")
    logger.info("Processing complete, exiting.")


# Run the event loop
asyncio.run(main())
