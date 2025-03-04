import base64
import json
import os
import subprocess
from datetime import datetime as real_datetime
from types import SimpleNamespace
from unittest import mock
from unittest.mock import mock_open
import pytest
import paho.mqtt.client as mqtt_client
import asyncio

from autopatchdatatypes import CrashDetail

import fuzzing_service as fuzzing_service

# Import the function to test from the updated module.
from fuzzing_service import (
    CONST_FUZZ_SVC_CONFIG,
    extract_crashes,
    init_logging,
    load_config,
    compile_program_run_fuzzer,
    write_crashes_csv,
    MapCrashDetailAsCloudEvent,
    MapCrashDetailsAsCloudEvents,
    produce_output,
    main,
)

# A fixed datetime class to always return the same timestamp.
class FixedDatetime:
    @classmethod
    def now(cls, tz=None):
        dt = real_datetime(2025, 1, 1, 12, 0, 0)
        return dt if tz is None else dt.replace(tzinfo=tz)

    @classmethod
    def fromisoformat(cls, iso_str):
        return FixedDatetime.now()


# A dummy logger to capture logger calls.
class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, msg):
        self.messages.append(msg)

    def debug(self, msg):
        self.messages.append(msg)

    def error(self, msg):
        self.messages.append(msg)

    def log(self, msg, *args, **kwargs):
        self.messages.append(msg)


@pytest.fixture(autouse=True)
def fake_message_broker_client(monkeypatch):
    class DummyMessageBrokerClient:
        def __init__(self, *args, **kwargs):
            self.client = mock.Mock(spec=mqtt_client.Client)

        def publish(self, topic, message):
            # Optionally, record calls or simply do nothing.
            # self.client.publish(topic, message)
            pass

    monkeypatch.setattr(
        fuzzing_service, "MessageBrokerClient", DummyMessageBrokerClient
    )


@pytest.fixture(autouse=True)
def patch_datetime(monkeypatch):
    monkeypatch.setattr("fuzzing_service.datetime", FixedDatetime)


@pytest.fixture(autouse=True)
def patch_datetime(monkeypatch):
    def dummymain():
        pass

    monkeypatch.setattr("fuzzing_service.main", dummymain)


@pytest.fixture
def dummy_logger(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr("fuzzing_service.logger", logger)

def dummy_run_success(*args, **kwargs):
    # Return an object with stdout and stderr attributes.
    dummy = SimpleNamespace(stdout="compile ok", stderr="")
    return dummy

@pytest.mark.asyncio
async def test_MapCrashDetailAsCloudEvent():
    """Test that a CrashDetail object is correctly mapped to a CloudEvent."""
    crash_detail = CrashDetail(
        "test_exe", base64.b64encode(b"crash_data").decode("utf-8"), True
    )
    event = await MapCrashDetailAsCloudEvent(crash_detail)
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
    """Test that a list of CrashDetail objects are mapped to CloudEvents asynchronously."""
    crash_details = [
        CrashDetail("test_exe1", base64.b64encode(b"crash1").decode("utf-8"), True),
        CrashDetail("test_exe2", base64.b64encode(b"crash2").decode("utf-8"), False),
    ]
    events = await MapCrashDetailsAsCloudEvents(crash_details)
    assert len(events) == 2
    assert events[0]["subject"] == "test_exe1"
    assert events[1]["subject"] == "test_exe2"


# --------------
# Tests for init_logging
# --------------


def test_init_logging_file_not_found(monkeypatch, capsys):
    # Force os.path.exists to always return False
    monkeypatch.setattr(os.path, "exists", lambda path: False)
    # Call init_logging with a dummy path.
    logger = init_logging("dummy_logging.json", "test_app")
    captured = capsys.readouterr().out
    assert "not found" in captured
    assert "Falling back to basic logging configuration." in captured
    # Even in fallback, a logger with the given name is returned.
    assert logger.name == "test_app"


def test_init_logging_invalid_json(monkeypatch, capsys):
    # Simulate that the logging config file exists.
    monkeypatch.setattr(os.path, "exists", lambda path: True)
    # Provide invalid JSON content.
    m = mock_open(read_data="not valid json")
    monkeypatch.setattr("builtins.open", m)
    logger = init_logging("dummy_logging.json", "test_app")
    captured = capsys.readouterr().out
    assert "Error decoding JSON" in captured or "Unexpected error" in captured
    assert "Falling back to basic logging configuration." in captured
    assert logger.name == "test_app"


def test_init_logging_valid(monkeypatch, capsys):
    # Provide a valid logging configuration.
    valid_config = {
        "version": 1,
        "formatters": {"default": {"format": "%(levelname)s:%(message)s"}},
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "stream": "ext://sys.stdout",
            }
        },
        "loggers": {
            "test_app": {
                "handlers": ["console"],
                "level": "DEBUG",
                "propagate": False,
            }
        },
    }
    config_str = json.dumps(valid_config)
    # Simulate file exists.
    monkeypatch.setattr(os.path, "exists", lambda path: True)
    m = mock_open(read_data=config_str)
    monkeypatch.setattr("builtins.open", m)
    logger = init_logging("dummy_logging.json", "test_app")
    # The logger should be configured and have logged the initialization.
    captured = capsys.readouterr().out
    assert "Logger initialized successfully." in captured
    assert logger.name == "test_app"


# --------------
# Tests for load_config
# --------------


def test_load_config_valid(monkeypatch, tmp_path):
    # Create a temporary config file.
    config_data = {"logging_config": "dummy_logging.json", "appname": "dummy_app"}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config_data), encoding="utf-8")
    # Set the environment variable.
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, str(config_file))
    # Call load_config and verify the output.
    loaded_config = load_config()
    assert loaded_config == config_data


def test_load_config_no_env(monkeypatch):
    # Ensure the environment variable is not set.
    monkeypatch.delenv(CONST_FUZZ_SVC_CONFIG, raising=False)
    with pytest.raises(SystemExit):
        load_config()


def test_load_config_file_not_found(monkeypatch):
    # Set the env var to a non-existent file.
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, "nonexistent_config.json")
    # Monkey-patch open to raise FileNotFoundError.
    monkeypatch.setattr(
        "builtins.open", lambda f, **kw: (_ for _ in ()).throw(FileNotFoundError)
    )
    with pytest.raises(SystemExit):
        load_config()


def test_load_config_invalid_utf8(monkeypatch):
    # Set env var to a dummy file.
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, "dummy_config.json")

    # Monkey-patch open to raise UnicodeDecodeError.
    def fake_open(*args, **kwargs):
        raise UnicodeDecodeError("codec", b"", 0, 1, "reason")

    monkeypatch.setattr("builtins.open", fake_open)
    with pytest.raises(SystemExit):
        load_config()


def test_load_config_invalid_json(monkeypatch, tmp_path):
    # Create a temporary config file with invalid JSON.
    config_file = tmp_path / "config.json"
    config_file.write_text("invalid json", encoding="utf-8")
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, str(config_file))
    with pytest.raises(SystemExit):
        load_config()

# --------------
# Tests for compile_program_run_fuzzer
# --------------

def test_run_fuzzer_compile_failure(monkeypatch):
    # Set up config.
    fuzzing_service.config = {
        "compiler_warning_flags": "-w",
        "compiler_feature_flags": "-f",
        "afl_tool_child_process_memory_limit_mb": 128,
    }
    executable_name = "failprog"
    dummy_args = (
        "/dummy",
        "failprog.c",
        "/dummy/compiled",
        "/dummy/compiler",
        "/dummy/fuzzer",
        "/dummy/seed",
        "/dummy/output",
        10,
    )

    # Simulate compile failure.
    def fake_run_fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], output="error")

    monkeypatch.setattr(subprocess, "run", fake_run_fail)
    ret = compile_program_run_fuzzer(
        executable_name, *dummy_args, isInputFromFile=False
    )
    assert ret is False

def test_run_fuzzer_popen_failure(monkeypatch):
    # Set up config.
    fuzzing_service.config = {
        "compiler_warning_flags": "-w",
        "compiler_feature_flags": "-f",
        "afl_tool_child_process_memory_limit_mb": 128,
    }
    executable_name = "failprog"
    dummy_args = (
        "/dummy",
        "failprog.c",
        "/dummy/compiled",
        "/dummy/compiler",
        "/dummy/fuzzer",
        "/dummy/seed",
        "/dummy/output",
        10,
    )
    # Let the compile succeed.
    monkeypatch.setattr(subprocess, "run", dummy_run_success)
    # Simulate a failure in the fuzzer run by having Popen raise an Exception.
    monkeypatch.setattr(
        subprocess,
        "Popen",
        lambda *args, **kwargs: (_ for _ in ()).throw(Exception("Popen failed")),
    )
    ret = compile_program_run_fuzzer(
        executable_name, *dummy_args, isInputFromFile=False
    )
    assert ret is False


# --------------
# Tests for extract_crashes
# --------------


def test_extract_crashes_no_directory(monkeypatch):
    # Simulate os.listdir raising FileNotFoundError.
    monkeypatch.setattr(
        os, "listdir", lambda path: (_ for _ in ()).throw(FileNotFoundError)
    )
    crashes = extract_crashes(
        "/nonexistent/path", "testprog", timeout=5, isInputFromFile=True
    )
    assert crashes == []
