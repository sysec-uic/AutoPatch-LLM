from dataclasses import dataclass


@dataclass
class TransformerMetadata:
    """
    Represents metadata about the transformer model (llm) and it's
    configuration used for patch generation.
    """

    llm_name: str
    llm_version: str
    llm_flavor: str
    # llm_configured_top_p: float
    # llm_configured_temperature: float
    # llm_autopatch_system_prompt_version: str
    # llm_autopatch_user_system_prompt_version: str
