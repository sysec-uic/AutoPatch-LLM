import logging
from datetime import datetime as real_datetime
from datetime import timezone
from unittest import mock

import code_property_graph_generator as code_property_graph_generator
import paho.mqtt.client as mqtt_client
import pytest
from code_property_graph_generator import remove_joern_scan_temp_file
from cpg_svc_config import CpgSvcConfig


def mock_CpgSvcConfig() -> CpgSvcConfig:
    mock_config = {
        "version": "0.9.1-beta",
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
