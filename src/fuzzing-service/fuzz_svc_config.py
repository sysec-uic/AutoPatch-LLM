from dataclasses import dataclass


@dataclass
class FuzzSvcConfig:
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
    make_tool_full_path: str
    iconv_tool_timeout: int
