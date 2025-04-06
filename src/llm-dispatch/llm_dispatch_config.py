from dataclasses import dataclass
from typing import Dict, List


@dataclass
class LLMDispatchConfig:
    devonlyinputfilepath: str
    appName: str
    appVersion: str
    appDescription: str
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
    api: Dict[str, str]
    model_router_base_url: str
    model_router_fallback_model: str
    model_router_max_concurrent_requests: int
    model_router_retry_attempts: int
    model_router_timeout_ms: int
    model_router_retry_delay_ms: int
    cache_enabled: bool
    cache_dir: str
    cache_expiration: int
    models: List[Dict[str, object]]
