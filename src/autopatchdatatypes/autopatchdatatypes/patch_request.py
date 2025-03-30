from autopatchdatatypes.crash_detail import CrashDetail
from dataclasses import dataclass


@dataclass
class PatchRequest:
    """
    Represents a request to patch an executable.

    Attributes:
        executable_name (str): The name of the executable to be patched.
        crash_detail (CrashDetail): Details about the crash that occurred.
        bug_static_context (str): Static context of the bug.
        unsafe_source_snippet (str): Unsafe source code snippet related to the bug.
        # retrieval_vectors (str): Retrieval vectors for the patch request.
    """

    executable_name: str
    crash_detail: CrashDetail
    bug_static_context: str
    unsafe_source_snippet: str
    iso_8601_timestamp: str

    # TODO get timestamp from cloudevent
    # for next version using LightRAG or similar
    # retreival_vectors: str
