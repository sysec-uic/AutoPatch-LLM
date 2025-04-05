from dataclasses import dataclass


@dataclass
class CpgSvcConfig:
    version: str
    appname: str
    logging_config: str
    scan_tool_full_path: str
    message_broker_host: str
    message_broker_port: int
    message_broker_protocol: str
    concurrency_threshold: int
    cpg_svc_scan_result_output_topic: str
    cpg_svc_input_codebase_path: str
    cpg_svc_output_path: str
