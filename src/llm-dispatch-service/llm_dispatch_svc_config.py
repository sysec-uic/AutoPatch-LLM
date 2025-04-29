from dataclasses import dataclass
from typing import Dict, List


@dataclass
class LLMDispatchSvcConfig:
    appName: str
    appVersion: str
    appDescription: str
    cpg_gen_wait_time: int
    cpg_scan_result_input_topic: str
    input_codebase_full_path: str
    system_prompt_full_path: str
    user_prompt_full_path: str
    logging_config: str
    default_model: str
    default_api_provider: str
    default_in_memory_provider: str
    default_max_tokens: int
    default_temperature: int
    default_top_p: int
    default_frequency_penalty: int
    default_presence_penalty: int
    message_broker_client_id: str
    message_broker_host: str
    message_broker_port: int
    message_broker_topics: Dict[str, str]
    model_router_base_url: str
    model_router_fallback_model: str
    model_router_max_concurrent_requests: int
    model_router_retry_attempts: int
    model_router_timeout_ms: int
    model_router_retry_delay_ms: int
    models: List[str]
