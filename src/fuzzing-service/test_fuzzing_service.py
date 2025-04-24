import base64
import logging
import os
import subprocess
from datetime import datetime as real_datetime
from datetime import timezone
from types import SimpleNamespace
from unittest import mock

import fuzzing_service as fuzzing_service
import paho.mqtt.client as mqtt_client
import pytest
from fuzz_svc_config import FuzzSvcConfig

# Import the function to test from the updated module.
from fuzzing_service import (
    compile_program,
    extract_crashes,
    map_crash_detail_as_cloudevent,
    map_crashdetails_as_cloudevents,
    produce_output,
    write_crashes_csv,
)

from autopatchdatatypes import CrashDetail


def mock_FuzzSvcConfig() -> FuzzSvcConfig:
    mock_config = {
        "version": "0.8.0-beta",
        "appname": "autopatch.fuzzing-service",
        "logging_config": "config/logging-config.json",
        "concurrency_threshold": 10,
        "message_broker_host": "mosquitto",
        "message_broker_port": 1883,
        "message_broker_protocol": "mqtt",
        "fuzz_svc_output_topic": "autopatch/crash_detail",
        "fuzz_svc_input_codebase_path": "/workspace/AutoPatch-LLM/assets/input_codebase",
        "fuzz_svc_output_path": "data/fuzz_svc_output",
        "compiler_warning_flags": "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow",
        "compiler_feature_flags": "-m32 -fno-stack-protector -O1 -fsanitize=address",
        "fuzzer_tool_name": "afl",
        "fuzzer_tool_timeout_seconds": 120,
        "fuzzer_tool_version": "afl-fuzz++4.09c",
        "afl_tool_full_path": "/usr/bin/afl-fuzz",
        "afl_tool_seed_input_path": "seed_input",
        "afl_tool_output_path": "data/afl_tool_output",
        "afl_tool_child_process_memory_limit_mb": 6000,
        "afl_tool_compiled_binary_executables_output_path": "bin",
        "afl_compiler_tool_full_path": "/usr/bin/afl-gcc",
        "make_tool_full_path": "/usr/bin/make",
        "iconv_tool_timeout": 120,
    }
    return FuzzSvcConfig(**mock_config)


# A dummy logger to capture logger calls.
class DummyLogger(logging.Logger):
    def __init__(self):
        super().__init__(name="dummy")
        self.messages = []
        self.level = logging.DEBUG  # Add the level attribute

    def info(self, msg):
        self.messages.append(msg)

    def debug(self, msg):
        self.messages.append(msg)

    def error(self, msg):
        self.messages.append(msg)

    def log(self, level, msg, *args, **kwargs):
        self.messages.append(msg)


@pytest.fixture(autouse=True)
def mock_message_broker_client(monkeypatch):
    class DummyMessageBrokerClient:
        def __init__(self, *args, **kwargs):
            self.client = mock.Mock(spec=mqtt_client.Client)

        async def publish(self, topic, message) -> str:
            # Optionally, record calls or simply do nothing.
            # self.client.publish(topic, message)
            pass

    monkeypatch.setattr(
        fuzzing_service, "MessageBrokerClient", DummyMessageBrokerClient
    )
    monkeypatch.setattr("fuzzing_service.get_current_timestamp", FixedDatetime.now)


# A fixed datetime class to always return the same timestamp.
class FixedDatetime:
    @classmethod
    def now(cls) -> str:
        dt = (
            real_datetime(2025, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
            .isoformat(timespec="seconds")
            .replace("+00:00", "Z")
        )
        return dt

    @classmethod
    def fromisoformat(cls, iso_str):
        return real_datetime.fromisoformat(iso_str.replace("Z", "+00:00"))


@pytest.fixture(autouse=True)
def patch_datetime(monkeypatch):
    monkeypatch.setattr("fuzzing_service.datetime", FixedDatetime)


@pytest.fixture(autouse=True)
def mock_logger(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr("fuzzing_service.logger", logger)
    return logger


def mock_run_success(*args, **kwargs):
    # Return an object with stdout and stderr attributes.
    return SimpleNamespace(stdout="compile ok", stderr="")


# --------------
# Async tests
# --------------


@pytest.mark.asyncio
async def test_MapCrashDetailAsCloudEvent():
    """Test that a CrashDetail object is correctly mapped to a CloudEvent."""

    # Assemble
    crash_detail = CrashDetail(
        "test_exe", base64.b64encode(b"crash_data").decode("utf-8"), True
    )

    # Act
    event = await map_crash_detail_as_cloudevent(crash_detail)

    # Assert
    assert event is not None
    assert event["type"] == "autopatch.crashdetail"
    assert event["source"] == "autopatch.fuzzing-service"
    assert event["subject"] == "test_exe"
    assert event.data["executable_name"] == "test_exe"
    assert event.data["crash_detail_base64"] == base64.b64encode(b"crash_data").decode(
        "utf-8"
    )
    assert event.data["is_input_from_file"] is True


@pytest.mark.asyncio
async def test_MapCrashDetailsAsCloudEvents():
    # Assemble
    fuzzing_service.config = mock_FuzzSvcConfig()
    """Test that a list of CrashDetail objects are mapped to CloudEvents asynchronously."""
    crash_details = [
        CrashDetail("test_exe1", base64.b64encode(b"crash1").decode("utf-8"), True),
        CrashDetail("test_exe2", base64.b64encode(b"crash2").decode("utf-8"), False),
    ]

    # Act
    events = await map_crashdetails_as_cloudevents(crash_details)

    # Assert
    assert len(events) == 2
    assert events[0]["subject"] == "test_exe1"
    assert events[1]["subject"] == "test_exe2"


@pytest.mark.asyncio
async def test_produce_output(mock_logger):
    # Assemble
    fuzzing_service.config = mock_FuzzSvcConfig()
    """Test producing output asynchronously, ensuring logger output is correct."""
    crash_details = [
        CrashDetail("test_exe", base64.b64encode(b"crash_data").decode("utf-8"), True)
    ]

    # Act
    await produce_output(crash_details)

    # Assert
    assert "Producing 1 CloudEvents." in mock_logger.messages


@pytest.mark.asyncio
async def test_produce_output_with_multiple_events(mock_logger):
    """Test producing multiple CloudEvents asynchronously."""
    # Assemble
    fuzzing_service.config = mock_FuzzSvcConfig()
    crash_details = [
        CrashDetail("test_exe1", base64.b64encode(b"crash1").decode("utf-8"), True),
        CrashDetail("test_exe2", base64.b64encode(b"crash2").decode("utf-8"), False),
    ]

    # Act
    await produce_output(crash_details)

    # Assert
    assert "Producing 2 CloudEvents." in mock_logger.messages


# --------------
# Tests for compile_program
# --------------


def test_compile_failure(monkeypatch):
    # Assemble
    # Set up config.
    fuzzing_service.config = mock_FuzzSvcConfig()
    fuzzing_service.config.compiler_warning_flags = "-w"
    fuzzing_service.config.compiler_feature_flags = "-f"
    fuzzing_service.config.afl_tool_child_process_memory_limit_mb = 128

    dummy_args = (
        "failprog.c",
        "/dummy/compiled",
        "/dummy/compiler",
        10,
    )

    # Simulate compile failure.
    def fake_run_fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], output="error")

    monkeypatch.setattr(subprocess, "run", fake_run_fail)

    # Act
    ret = compile_program(*dummy_args)

    # Assemble
    assert ret is False


# --------------
# Tests for extract_crashes
# --------------


def test_extract_crashes_no_directory(monkeypatch):
    # Assemble
    # Simulate os.listdir raising FileNotFoundError.
    monkeypatch.setattr(
        os, "listdir", lambda path: (_ for _ in ()).throw(FileNotFoundError)
    )
    # Act
    crashes = extract_crashes(
        "/nonexistent/path", "testprog", timeout=5, isInputFromFile=True
    )
    # Assert
    assert crashes == []


# --------------
# Tests for write_crashes_csv
# --------------


def test_write_crashes_csv_new_file_input_from_file(monkeypatch, tmp_path):
    """
    Test that when the CSV file does not exist, the header is written,
    and when isInputFromFile is True, the crashes (as strings) are written.
    """
    # Assemble
    csv_path = tmp_path / "crashes.csv"
    executable_name = "test_exe"
    dummy_base64_messages = ["crash1", "crash2"]
    dummy_base64_messages = [
        base64.b64encode(msg.encode("utf-8")).decode("utf-8")
        for msg in dummy_base64_messages
    ]
    crash_details = [
        CrashDetail(executable_name, base64_message, True)
        for base64_message in dummy_base64_messages
    ]

    # Act
    # Call the function (it should create the file and write the header).
    write_crashes_csv(crash_details, str(csv_path))

    # Assert
    # Read back the file.
    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # Verify header is present.
    assert lines[0] == "timestamp,executable_name,crash_detail_base64,isInputFromFile"
    # Each crash line uses the fixed timestamp.
    detail = crash_details[0]
    expected_line1 = (
        f"2025-01-01T12:00:00Z,"
        f"{detail.executable_name},"
        f"{detail.base64_message},"
        f"{detail.is_input_from_file}"
    )
    detail = crash_details[1]
    expected_line2 = (
        f"2025-01-01T12:00:00Z,"
        f"{detail.executable_name},"
        f"{detail.base64_message},"
        f"{detail.is_input_from_file}"
    )
    assert lines[1] == expected_line1
    assert lines[2] == expected_line2


def test_write_crashes_csv_existing_file_no_header(monkeypatch, tmp_path):
    """
    Test that if the CSV file already exists and is non-empty,
    the header is not re-written.
    """
    # Assemble
    csv_path = tmp_path / "crashes.csv"
    # Create a file with a header already.
    header = "timestamp,executable_name,crash_detail,isInputFromFile\n"
    csv_path.write_text(header, encoding="utf-8")

    executable_name = "test_exe"
    dummy_base64_messages = ["crash1", "crash2"]
    dummy_base64_messages = [
        base64.b64encode(msg.encode("utf-8")).decode("utf-8")
        for msg in dummy_base64_messages
    ]
    crash_details = [
        CrashDetail(executable_name, crash, False) for crash in dummy_base64_messages
    ]

    # Act
    write_crashes_csv(crash_details, str(csv_path))

    # Assert
    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # The first line should still be the original header.
    assert lines[0] == "timestamp,executable_name,crash_detail,isInputFromFile"

    # Compute the expected hex values.
    expected_line1 = (
        f"2025-01-01T12:00:00Z,"
        f"{crash_details[0].executable_name},"
        f"{crash_details[0].base64_message},"
        f"{crash_details[0].is_input_from_file}"
    )
    expected_line2 = (
        f"2025-01-01T12:00:00Z,"
        f"{crash_details[1].executable_name},"
        f"{crash_details[1].base64_message},"
        f"{crash_details[1].is_input_from_file}"
    )
    assert lines[1] == expected_line1
    assert lines[2] == expected_line2


def test_write_crashes_csv_empty_crashes(monkeypatch, tmp_path):
    """
    Test that when the crashes list is empty and the file does not exist,
    only the header is written.
    """
    # Assemble
    csv_path = tmp_path / "crashes.csv"
    crashes = []

    # Act
    write_crashes_csv(crashes, str(csv_path))

    # Assert
    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    # Only the header should be present.
    assert lines == ["timestamp,executable_name,crash_detail_base64,isInputFromFile"]


def test_write_crashes_csv_creates_directory(monkeypatch, tmp_path):
    """
    Test that the function creates the output directory if it does not exist.
    """
    # Define a CSV path in a subdirectory that does not exist.
    subdir = tmp_path / "nonexistent_dir"
    csv_path = subdir / "crashes.csv"
    executable_name = "test_exe"
    base64_encoded_message = base64.b64encode(b"crash_in_dir").decode("utf-8")
    crash_details = [CrashDetail(executable_name, base64_encoded_message, True)]

    # Ensure the subdirectory does not exist yet.
    assert not subdir.exists()

    write_crashes_csv(crash_details, str(csv_path))

    # Now the directory should have been created.
    assert subdir.exists()

    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    expected_line = (
        f"2025-01-01T12:00:00Z,"
        f"{crash_details[0].executable_name},"
        f"{crash_details[0].base64_message},"
        f"{crash_details[0].is_input_from_file}"
    )
    # Header is the first line.
    assert lines[1] == expected_line


def test_write_crashes_csv_logger_called(tmp_path, mock_logger):
    """
    Test that logger.info is called for each crash.
    """
    # Assemble
    csv_path = tmp_path / "crashes.csv"
    executable_name = "test_exe"
    log_crash1_base64 = base64.b64encode(b"log_crash1").decode("utf-8")
    log_crash2_base64 = base64.b64encode(b"log_crash2").decode("utf-8")
    dummy_base64_messages = [log_crash1_base64, log_crash2_base64]
    crash_details = [
        CrashDetail(executable_name, crash, True) for crash in dummy_base64_messages
    ]

    # Act
    write_crashes_csv(crash_details, str(csv_path))

    # Assert
    # Verify that a log entry was recorded for each crash.
    expected_messages = [f"  - {crash}" for crash in crash_details]
    assert mock_logger.messages == expected_messages
