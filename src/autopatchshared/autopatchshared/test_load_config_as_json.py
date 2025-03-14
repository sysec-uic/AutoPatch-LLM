import json
import logging
import pytest
from typing import Final
from autopatchshared import load_config_as_json


CONST_DUMMY_SVC_CONFIG: Final[str] = "CONST_DUMMY_SVC_CONFIG"


# A dummy logger to capture logger calls.
class DummyLogger(logging.Logger):
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


def test_load_config_valid(monkeypatch, tmp_path):
    # Create a temporary config file.
    config_data = {"logging_config": "dummy_logging.json", "appname": "dummy_app"}
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config_data), encoding="utf-8")
    # Mock the environment variable to provide a valid path to the configuration file.
    monkeypatch.setenv(CONST_DUMMY_SVC_CONFIG, str(config_file))

    # Call load_config and verify the output.
    loaded_config = load_config_as_json(str(config_file), DummyLogger())

    # Call load_config and verify the output.
    loaded_config = load_config_as_json(str(config_file), DummyLogger())
    assert loaded_config == config_data


def test_load_config_file_not_found(monkeypatch):
    # Set the env var to a non-existent file.
    monkeypatch.setenv(CONST_DUMMY_SVC_CONFIG, "nonexistent_config.json")
    # Monkey-patch open to raise FileNotFoundError.
    monkeypatch.setattr(
        "builtins.open", lambda f, **kw: (_ for _ in ()).throw(FileNotFoundError)
    )
    with pytest.raises(SystemExit):
        load_config_as_json(CONST_DUMMY_SVC_CONFIG, DummyLogger())


def test_load_config_invalid_utf8(monkeypatch):
    # Set env var to a dummy file.
    monkeypatch.setenv(CONST_DUMMY_SVC_CONFIG, "dummy_config.json")

    # Monkey-patch open to raise UnicodeDecodeError.
    def fake_open(*args, **kwargs):
        raise UnicodeDecodeError("codec", b"", 0, 1, "reason")

    monkeypatch.setattr("builtins.open", fake_open)
    with pytest.raises(SystemExit):
        load_config_as_json(CONST_DUMMY_SVC_CONFIG, DummyLogger())


def test_load_config_invalid_json(monkeypatch, tmp_path):
    # Create a temporary config file with invalid JSON.
    config_file = tmp_path / "config.json"
    config_file.write_text("invalid json", encoding="utf-8")
    monkeypatch.setenv(CONST_DUMMY_SVC_CONFIG, str(config_file))
    with pytest.raises(SystemExit):
        load_config_as_json(CONST_DUMMY_SVC_CONFIG, DummyLogger())
