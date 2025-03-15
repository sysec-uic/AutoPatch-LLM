from dataclasses import dataclass


@dataclass
class PatchEvalConfig:
    version: str
    appname: str
    logging_config: str
    crashes_events: str
    patch_eval_results: str
    patched_codes_path: str
    executables_path: str
    compiler_warning_flags: str
    temp_crashes_path: str
    compile_timeout: int
    run_timeout: int
    autopatch_crash_detail_input_topic: str
    message_broker_host: str
    message_broker_port: int = 1833
