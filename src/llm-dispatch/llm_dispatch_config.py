from dataclasses import dataclass
from typing import Dict, List


@dataclass
class LLMDispatchConfig:
    appName: str
    appVersion: str
    appDescription: str
    logging_config: str
    message_broker_host: str
    message_broker_port: int
    message_broker_patch_request_topic: str
    message_broker_patch_response_topic: str
    message_broker_client_id: str
    systemprompt_full_path: str
    userprompt_full_path: str
    model_router_base_url: str
    model_router_fallback_model: str
    model_router_max_concurrent_requests: int
    api_timeout_seconds: int
    api_retry_attempts: int
    api_retry_delay_ms: int
    default_max_tokens: int
    default_temperature: int
    default_top_p: int
    models: List[Dict[str, str]]
    # "default_frequency_penalty": 0,
    # "default_presence_penalty": 0,
    # "cache_enabled": false,
    # "cache_dir": "/workspace/AutoPatch-LLM/src/llm-dispatch/data/cache",
    # "cache_expiration": 3600,
