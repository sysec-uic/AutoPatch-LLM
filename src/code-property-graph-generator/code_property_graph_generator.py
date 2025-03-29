import asyncio
import base64
import logging
import logging.config
import os
import signal
import subprocess
import sys
from datetime import datetime
from typing import Final, List

from autopatchdatatypes import CpgDetail
from autopatchpubsub import MessageBrokerClient
from autopatchshared import init_logging, load_config_as_json, get_current_timestamp
from cloudevents.http import CloudEvent
from cpg_svc_config import CpgSvcConfig

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


def extract_code_property_graph():
    raise NotImplementedError


def write_code_property_graphs_as_csv(crash_details: List[CpgDetail], csv_path: str) -> None:
    raise NotImplementedError


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
        logger.debug(
            f"Producing on Topic: {config.cpg_svc_output_topic}"  # noqa: F821
        )
        logger.debug(f"Producing CloudEvent: {event}")
        message_broker_client.publish(
            config.cpg_svc_output_topic, str(event)  # noqa: F821
        )

    cpg_details_cloud_events: List[CloudEvent] = (
        await map_crashdetails_as_cloudevents(cpg_details)
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

    csv_path: Final[str] = os.path.join(config.cpg_svc_output_path, "code-property-graphs.csv")
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

    CPG_SVC_END_TIMESTAMP: Final[str] = get_current_timestamp()
    time_delta = datetime.fromisoformat(
        CPG_SVC_END_TIMESTAMP
    ) - datetime.fromisoformat(CPG_SVC_START_TIMESTAMP)
    logger.info(f"Total Processing Time Elapsed: {time_delta}")
    logger.info("Processing complete, exiting.")


# Run the event loop
asyncio.run(main())
