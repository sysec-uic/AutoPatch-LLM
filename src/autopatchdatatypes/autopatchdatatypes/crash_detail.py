import base64
from dataclasses import dataclass


@dataclass
class CrashDetail:
    executable_name: str
    base64_message: str  # Must be Base64-encoded string
    is_input_from_file: bool

    def __post_init__(self):
        # Validate that `message` is a valid base64-encoded string
        if not self._is_base64_encoded(self.base64_message):
            raise ValueError("The message must be a valid base64-encoded byte string.")

    @staticmethod
    def _is_base64_encoded(data: str) -> bool:
        try:
            # Decode and re-encode to verify valid base64
            decoded = base64.b64decode(data, validate=True)
            return base64.b64encode(decoded).decode("utf-8") == data
        except (base64.binascii.Error, ValueError):
            return False
