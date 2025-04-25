from dataclasses import dataclass
from typing import List


@dataclass
class PatchEvalConfig:
    appname: str
    version: str
    input_codebase_full_path: str
    logging_config: str
    patch_eval_results_full_path: str
    patched_codes_path: str
    executables_full_path: str
    compiler_tool_full_path: str
    compiler_warning_flags: str
    compiler_feature_flags: str
    compile_timeout: int
    run_timeout: int
    autopatch_patch_response_input_topic: str
    autopatch_crash_detail_input_topic: str
    model_names: List[str]
    message_broker_host: str
    message_broker_port: int = 1833
