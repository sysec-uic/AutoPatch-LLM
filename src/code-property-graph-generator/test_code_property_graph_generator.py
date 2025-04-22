import logging
from datetime import datetime as real_datetime
from datetime import timezone
from unittest import mock

import code_property_graph_generator as code_property_graph_generator
import paho.mqtt.client as mqtt_client
import pytest
from cpg_svc_config import CpgSvcConfig
from code_property_graph_generator import (
    remove_joern_scan_temp_file,
    scan_cpg,
    map_scan_result_as_cloudevent,
    map_scan_results_as_cloudevents,
    produce_output,
    #load_config,
    unmarshall_raw_joern_scan_result,
    unmarshall_raw_joern_scan_results,
)

# from autopatchdatatypes import CpgScanResult

class DummyProcess:
    def __init__(self, returncode=0, stdout=b"output", stderr=b"error"):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr
        self._poll_return = poll_return
        self.pid = pid

    def poll(self):
        return self._poll_return

    async def communicate(self, input=None):
        return (self._stdout, self._stderr)

    def kill(self):
        self.returncode = -1

def mock_CpgSvcConfig() -> CpgSvcConfig:
    mock_config = {
        "version": "0.7.3-alpha",
        "appname": "autopatch.code-property-graph-generator",
        "logging_config": "/workspace/AutoPatch-LLM/src/code-property-graph-generator/config/dev-logging-config.json",
        "scan_tool_full_path": "/opt/joern/joern-cli/joern-scan",
        "concurrency_threshold": 10,
        "message_broker_host": "mosquitto",
        "message_broker_port": 1883,
        "cpg_svc_scan_result_output_topic": "autopatch/cpg-scan-result",
        "cpg_svc_input_codebase_path": "/workspace/AutoPatch-LLM/assets/input_codebase",
        "cpg_svc_output_path": "/workspace/AutoPatch-LLM/src/code-property-graph-generator/data",
    }

    return CpgSvcConfig(**mock_config)


# A dummy logger to capture logger calls.
class MockLogger:
    def __init__(self):
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
def fake_message_broker_client(monkeypatch):
    class DummyMessageBrokerClient:
        def __init__(self, *args, **kwargs):
            self.client = mock.Mock(spec=mqtt_client.Client)

        def publish(self, topic, message):
            # Optionally, record calls or simply do nothing.
            # self.client.publish(topic, message)
            pass

    monkeypatch.setattr(
        code_property_graph_generator, "MessageBrokerClient", DummyMessageBrokerClient
    )


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
    monkeypatch.setattr("code_property_graph_generator.datetime", FixedDatetime)


@pytest.fixture(autouse=True)
def mock_logger(monkeypatch):
    logger = MockLogger()
    monkeypatch.setattr("code_property_graph_generator.logger", logger)
    return logger


# --------------
# tests for remove_joern_scan_temp_file
# --------------


def test_file_does_not_exist(monkeypatch, mock_logger):
    # Assemble
    monkeypatch.setattr(
        code_property_graph_generator.os.path, "exists", lambda _: False
    )

    # Act
    remove_joern_scan_temp_file("fake/path/file.txt")

    # Assert
    assert mock_logger.messages == [
        "File 'fake/path/file.txt' does not exist, no need to delete."
    ]


def test_file_deleted_successfully(monkeypatch, mock_logger):
    # Assemble
    monkeypatch.setattr(code_property_graph_generator.os.path, "exists", lambda _: True)
    monkeypatch.setattr(code_property_graph_generator.os, "remove", mock.Mock())

    # Act
    remove_joern_scan_temp_file("fake/path/file.txt")

    # Assert
    assert mock_logger.messages == [
        "Attempting to delete fake/path/file.txt",
        "File 'fake/path/file.txt' has been deleted successfully.",
    ]


def test_file_not_found_during_delete(monkeypatch, mock_logger):

    # Assemble
    monkeypatch.setattr(code_property_graph_generator.os.path, "exists", lambda _: True)

    def raise_fnf_error(_):
        raise FileNotFoundError()

    monkeypatch.setattr(code_property_graph_generator.os, "remove", raise_fnf_error)

    # Act
    remove_joern_scan_temp_file("missing.txt")

    # Assert
    assert mock_logger.messages == [
        "Attempting to delete missing.txt",
        "File 'missing.txt' not found.",
    ]


def test_permission_error(monkeypatch, mock_logger):
    # Assemble
    monkeypatch.setattr(code_property_graph_generator.os.path, "exists", lambda _: True)

    def raise_perm_error(_):
        raise PermissionError()

    monkeypatch.setattr(code_property_graph_generator.os, "remove", raise_perm_error)

    # Act
    remove_joern_scan_temp_file("secure/file.txt")

    # Assert
    assert mock_logger.messages == [
        "Attempting to delete secure/file.txt",
        "Permission denied to delete the file 'secure/file.txt'.",
    ]


def test_generic_exception(monkeypatch, mock_logger):
    # Assemble
    monkeypatch.setattr(code_property_graph_generator.os.path, "exists", lambda _: True)

    def raise_generic(_):
        raise RuntimeError("unexpected failure")

    monkeypatch.setattr(code_property_graph_generator.os, "remove", raise_generic)

    # Act
    remove_joern_scan_temp_file("file.txt")

    # Assert
    assert mock_logger.messages == [
        "Attempting to delete file.txt",
        "Error occurred while deleting the file: unexpected failure",
    ]


def test_edge_case_empty_path(monkeypatch, mock_logger):
    # Assemble
    monkeypatch.setattr(
        code_property_graph_generator.os.path, "exists", lambda _: False
    )

    # Act
    remove_joern_scan_temp_file("")

    # Assert
    assert mock_logger.messages == ["File '' does not exist, no need to delete."]

# -------------------------------------
# Tests for scan_cpg
# -------------------------------------

def test_skip_non_c_file(monkeypatch, mock_logger):
    # remove temp‑file call should be a no‑op
    monkeypatch.setattr(
        remove_joern_scan_temp_file, "__call__", lambda path: None
    )

    # Act
    result = scan_cpg("/bin/joern-scan", "not_a_c_file.txt")

    # Assert
    assert result == []
    # last logger call should mention skipping
    assert any("is not a C file. Skipping" in m for m in mock_logger.messages)

def test_process_start_failure(monkeypatch, mock_logger):
    # stub out temp‑file removal
    monkeypatch.setattr(remove_joern_scan_temp_file, "__call__", lambda path: None)
    # Popen returns a process whose poll() != None immediately
    bad = DummyProcess(poll_return=1, pid=99)
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: bad)
    # unmarshall won't be called, but stub anyway
    monkeypatch.setattr(unmarshall_raw_joern_scan_results, "__call__", lambda lines: [])

    result = scan_cpg("/bin/joern-scan", "foo.c")

    assert result == []
    assert any("Process failed to start. PID: 99" in m for m in mock_logger.messages)


def test_no_result_lines(monkeypatch, mock_logger):
    monkeypatch.setattr(remove_joern_scan_temp_file, "__call__", lambda path: None)
    # simulate a running process (poll() is None) but no "Result:" in stdout/stderr
    proc = DummyProcess(poll_return=None, pid=123, stdout="hello\nworld", stderr="")
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)
    monkeypatch.setattr(unmarshall_raw_joern_scan_results, "__call__", lambda lines: [])

    result = scan_cpg("/bin/joern-scan", "foo.c")

    assert result == []
    # should still log "Parsed ScanResult: []"
    assert any("Parsed ScanResult: []" in m for m in mock_logger.messages)


def test_one_result_line_parsed(monkeypatch, mock_logger):
    monkeypatch.setattr(remove_joern_scan_temp_file, "__call__", lambda path: None)
    # simulate one Result: line
    out = "foo\nResult: this_is_a_test\nbar"
    proc = DummyProcess(poll_return=None, pid=555, stdout=out, stderr="")
    monkeypatch.setattr(subprocess, "Popen", lambda *a, **k: proc)

    # build a dummy CpgScanResult however your real constructor works
    dummy = CpgScanResult(score=123, message="this_is_a_test", file="f.c", line=1, function="main")
    monkeypatch.setattr(
        unmarshall_raw_joern_scan_results, "__call__", lambda lines: [dummy]
    )

    result = scan_cpg("/bin/joern-scan", "test.c")

    assert result == [dummy]
    # should log that we parsed one result
    assert any("Parsed ScanResult" in m for m in mock_logger.messages)