from dataclasses import dataclass
from typing import Dict


@dataclass
class LLMDispatchConfig:
    version: str
    appname: str
    logging_config: str
    concurrency_threshold: int
    message_broker_host: str
    message_broker_port: int
    message_broker_protocol: str
    temperature: float
    top_p: float
    max_tokens: int
    api_models: Dict[str, str]
    api_providers: Dict[str, str]
    api_secrets: Dict[str, str]
    in_memory_models: Dict[str, str]
    in_memory_providers: Dict[str, str]
    # in_memory_secrets: Dict[str, str]
