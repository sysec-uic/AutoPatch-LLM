import json
import os
import subprocess
from datetime import datetime as real_datetime
from types import SimpleNamespace
from unittest.mock import mock_open

import fuzzing_service as fuzzing_service
import pytest

# Import the function to test from the module.
from fuzzing_service import (
    CONST_FUZZ_SVC_CONFIG,
    extract_crashes,
    init_logging,
    load_config,
    run_fuzzer,
    write_crashes_csv,
)


# A fixed datetime class to always return the same timestamp.
class FixedDatetime:
    @classmethod
    def now(cls):
        # Return a fixed timestamp.
        return real_datetime(2025, 1, 1, 12, 0, 0)


# A dummy logger to capture logger.info calls.
class DummyLogger:
    def __init__(self):
        self.messages = []

    def info(self, msg):
        self.messages.append(msg)


# --- Pytest fixtures ---


# Automatically patch the datetime used in fuzzing_service.
@pytest.fixture(autouse=True)
def patch_datetime(monkeypatch):
    # The write_crashes_csv function does "from datetime import datetime",
    # so patch the datetime in the fuzzing_service module.
    monkeypatch.setattr("fuzzing_service.datetime", FixedDatetime)


# A fixture to patch the logger in the fuzzing_service module.
@pytest.fixture
def dummy_logger(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr("fuzzing_service.logger", logger)
    return logger


# --- Tests ---


def test_write_crashes_csv_new_file_input_from_file(tmp_path):
    """
    Test that when the CSV file does not exist, the header is written,
    and when inputFromFile is True, the crashes (as strings) are written.
    """
    csv_path = tmp_path / "crashes.csv"
    executable_name = "test_exe"
    crashes = ["crash1", "crash2"]

    # Call the function (it should create the file and write the header).
    write_crashes_csv(executable_name, crashes, str(csv_path), True)

    # Read back the file.
    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # Verify header is present.
    assert lines[0] == "timestamp,executable_name,crash_detail,inputFromFile"
    # Each crash line uses the fixed timestamp.
    expected_line1 = f"2025-01-01T12:00:00,{executable_name},crash1,True"
    expected_line2 = f"2025-01-01T12:00:00,{executable_name},crash2,True"
    assert lines[1] == expected_line1
    assert lines[2] == expected_line2


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
    expected_line1 = f"2025-01-01T12:00:00,{executable_name},{b'\xde\xad'.hex()},False"
    expected_line2 = f"2025-01-01T12:00:00,{executable_name},{b'\xbe\xef'.hex()},False"
    assert lines[1] == expected_line1
    assert lines[2] == expected_line2


def test_write_crashes_csv_empty_crashes(tmp_path):
    """
    Test that when the crashes list is empty and the file does not exist,
    only the header is written.
    """
    csv_path = tmp_path / "crashes.csv"
    executable_name = "test_exe"
    crashes = []

    write_crashes_csv(executable_name, crashes, str(csv_path), True)

    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # Only the header should be present.
    assert lines == ["timestamp,executable_name,crash_detail,inputFromFile"]


def test_write_crashes_csv_creates_directory(tmp_path):
    """
    Test that the function creates the output directory if it does not exist.
    """
    # Define a CSV path in a subdirectory that does not exist.
    subdir = tmp_path / "nonexistent_dir"
    csv_path = subdir / "crashes.csv"
    executable_name = "test_exe"
    crashes = ["crash_in_dir"]

    # Ensure the subdirectory does not exist yet.
    assert not subdir.exists()

    write_crashes_csv(executable_name, crashes, str(csv_path), True)

    # Now the directory should have been created.
    assert subdir.exists()

    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    expected_line = f"2025-01-01T12:00:00,{executable_name},crash_in_dir,True"
    # Header is the first line.
    assert lines[1] == expected_line


def test_write_crashes_csv_logger_called(tmp_path, dummy_logger):
    """
    Test that logger.info is called for each crash.
    """
    csv_path = tmp_path / "crashes.csv"
    executable_name = "test_exe"
    crashes = ["log_crash1", "log_crash2"]

    write_crashes_csv(executable_name, crashes, str(csv_path), True)

    # Verify that a log entry was recorded for each crash.
    expected_messages = [f"  - {crash}" for crash in crashes]
    assert dummy_logger.messages == expected_messages


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
# Tests for run_fuzzer
# --------------


class DummyProcess:
    def __init__(self, timeout_return=("dummy stdout", "dummy stderr")):
        self.pid = 1234
        self.called = 0
        self.timeout_return = timeout_return

    def communicate(self, timeout):
        self.called += 1
        return self.timeout_return


def dummy_run_success(*args, **kwargs):
    # Return an object with stdout and stderr attributes.
    dummy = SimpleNamespace(stdout="compile ok", stderr="")
    return dummy


def dummy_popen_success(*args, **kwargs):
    return DummyProcess()


def test_run_fuzzer_success(monkeypatch):
    # Set the global config required by run_fuzzer.
    fuzzing_service.config = {
        "compiler_warning_flags": "-w",
        "compiler_feature_flags": "-f",
        "afl_tool_child_process_memory_limit_mb": 128,
    }
    # Dummy arguments for run_fuzzer.
    executable_name = "testprog"
    codebase_path = "/dummy/codebase"
    program_path = "testprog.c"
    executables_afl_path = "/dummy/compiled"
    fuzzer_compiler_full_path = "/dummy/compiler"
    fuzzer_full_path = "/dummy/fuzzer"
    fuzzer_seed_input_path = "/dummy/seed"
    fuzzer_output_path = "/dummy/output"
    fuzzer_timeout = 10

    # Patch subprocess.run to simulate successful compile.
    monkeypatch.setattr(subprocess, "run", dummy_run_success)
    # Patch subprocess.Popen to simulate a process that returns valid output.
    monkeypatch.setattr(subprocess, "Popen", dummy_popen_success)

    # Patch os.path.exists to simulate that the fuzzer_stats file exists.
    def fake_exists(path):
        if path == os.path.join(fuzzer_output_path, executable_name, "fuzzer_stats"):
            return True
        return False

    monkeypatch.setattr(os.path, "exists", fake_exists)

    # Run with inputFromFile = True and then with False.
    ret = run_fuzzer(
        executable_name,
        codebase_path,
        program_path,
        executables_afl_path,
        fuzzer_compiler_full_path,
        fuzzer_full_path,
        fuzzer_seed_input_path,
        fuzzer_output_path,
        fuzzer_timeout,
        inputFromFile=True,
        isCodebase=True,
    )
    assert ret is True

    ret = run_fuzzer(
        executable_name,
        codebase_path,
        program_path,
        executables_afl_path,
        fuzzer_compiler_full_path,
        fuzzer_full_path,
        fuzzer_seed_input_path,
        fuzzer_output_path,
        fuzzer_timeout,
        inputFromFile=False,
        isCodebase=True,
    )
    assert ret is True


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
    ret = run_fuzzer(
        executable_name,
        *dummy_args,
        inputFromFile=False,
        isCodebase=True,
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
    ret = run_fuzzer(
        executable_name,
        *dummy_args,
        inputFromFile=False,
        isCodebase=True,
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
        "/nonexistent/path", "testprog", timeout=5, inputFromFile=True
    )
    assert crashes == []
