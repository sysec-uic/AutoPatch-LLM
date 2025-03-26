from dataclasses import dataclass


@dataclass
class PatchEvalConfig:
    version: str
    appname: str
    logging_config: str
    crashes_events: str
    patch_eval_results_full_path: str
    patched_codes_path: str
    executables_full_path: str
    compiler_tool_full_path: str
    compiler_warning_flags: str
    compiler_feature_flags: str
    temp_crashes_full_path: str
    compile_timeout: int
    run_timeout: int
    autopatch_crash_detail_input_topic: str
    message_broker_host: str
    message_broker_port: int = 1833
