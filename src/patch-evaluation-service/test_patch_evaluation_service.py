import json
import os
import subprocess
from datetime import datetime as real_datetime
from types import SimpleNamespace
from unittest.mock import mock_open

import patch_evaluation_service as patch_evaluation_service
import pytest

# Import the function to test from the module.
from patch_evaluation_service import (
    CONST_PATCH_EVAL_SVC_CONFIG,
    compile_file,
    init_logging,
    load_config,
    log_results,
    produce_output,
    run_file,
    write_crashes_csv,
)


# A fixed datetime class to always return the same timestamp.
class FixedDatetime:
    @classmethod
    def now(cls, tz=None):
        dt = real_datetime(2025, 1, 1, 12, 0, 0)
        return dt if tz is None else dt.replace(tzinfo=tz)


# A dummy logger to capture logger.info calls.
class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, msg):
        self.messages.append(msg)

        # --- Pytest fixtures ---


# Automatically patch the datetime used in patch_evaluation_service.
@pytest.fixture(autouse=True)
def patch_datetime(monkeypatch):
    # The write_crashes_csv function does "from datetime import datetime",
    # so patch the datetime in the patch_evaluation_service module.
    monkeypatch.setattr("patch_evaluation_service.datetime", FixedDatetime)


# A fixture to patch the logger in the patch_evaluation_service module.
@pytest.fixture
def dummy_logger(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr("patch_evaluation_service.logger", logger)
    return logger


# --- Tests ---


def test_write_crashes_csv_new_file(tmp_path):
    """
    Test that when the CSV file does not exist, the header is written
    """
    csv_path = tmp_path / "crashes.csv"
    executable_name = "test_exe"
    crash_detail = "01234abcde"
    return_code = 1

    # def write_crashes_csv(
    #     crash_detail: str,
    #     return_code: int,
    #     csv_path: str,
    #     inputFromFile: bool,
    # ) -> None:

    # Call the function (it should create the file and write the header).
    write_crashes_csv(crash_detail, return_code, csv_path, False)

    # Read back the file.
    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # head
    # Verify header is present.
    assert lines[0] == "timestamp,crash_detail,return_code,inputFromFile"
    # Each crash line uses the fixed timestamp.
    expected_line1 = f"2025-01-01T12:00:00Z,{crash_detail},{return_code},False"

    assert lines[1] == expected_line1


def test_write_crashes_csv_existing_file_no_header(tmp_path):
    """
    Test that if the CSV file already exists and is non-empty,
    the header is not re-written. Also test the raw-bytes branch.
    """
    csv_path = tmp_path / "crashes.csv"
    # Create a file with a header already.
    header = "timestamp,executable_name,crash_detail,inputFromFile\n"
    csv_path.write_text(header, encoding="utf-8")

    executable_name = "test_exe"
    # Provide crashes as raw bytes.
    crashes = [b"\xde\xad", b"\xbe\xef"]

    write_crashes_csv(executable_name, crashes, str(csv_path), False)

    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # The first line should still be the original header.
    assert lines[0] == "timestamp,executable_name,crash_detail,inputFromFile"

    # Compute the expected hex values.
    expected_line1 = f"2025-01-01T12:00:00Z,{executable_name},{b'\xde\xad'.hex()},False"
    expected_line2 = f"2025-01-01T12:00:00Z,{executable_name},{b'\xbe\xef'.hex()},False"
    assert lines[1] == expected_line1
    assert lines[2] == expected_line2
