from dataclasses import dataclass

from autopatchdatatypes.transformer_metadata import TransformerMetadata


@dataclass
class PatchResponse:
    """
    Represents a patch file for a specific executable program

    Attributes:
        executable_name (str): The name of the executable to be patched.
        patch_snippet_base64 (str):  # Must be Base64-encoded string
        TransformerMetadata TransformerMetadata:  # Metadata about the LLM model and configuration used for patch generation
        status (str):  # Status of the patch generation process (e.g., "success", "in_progress", "failed")
    """

    executable_name: str
    patch_snippet_base64: str
    TransformerMetadata: TransformerMetadata
    status: str
