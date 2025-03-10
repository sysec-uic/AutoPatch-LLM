import base64
import json
import os
import subprocess
from datetime import datetime as real_datetime
from types import SimpleNamespace
from unittest.mock import mock_open
import patch_evaluation_service as patch_evaluation_service
import pytest
from autopatchdatatypes import CrashDetail



# Import the function to test from the module.
from patch_evaluation_service import (
    CONST_PATCH_EVAL_SVC_CONFIG,
    compile_file,
    create_temp_crash_file,
    init_logging,
    load_config,
    log_results,
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
    monkeypatch.setenv(CONST_PATCH_EVAL_SVC_CONFIG, str(config_file))
    # Call load_config and verify the output.
    loaded_config = load_config()
    assert loaded_config == config_data


def test_load_config_no_env(monkeypatch):
    # Ensure the environment variable is not set.
    monkeypatch.delenv(CONST_PATCH_EVAL_SVC_CONFIG, raising=False)
    with pytest.raises(SystemExit):
        load_config()


# the error in this one i think is to do with my settings
def test_load_config_file_not_found(monkeypatch):
    # Set the env var to a non-existent file.
    monkeypatch.setenv(CONST_PATCH_EVAL_SVC_CONFIG, "nonexistent_config.json")
    # Monkey-patch open to raise FileNotFoundError.
    monkeypatch.setattr(
        "builtins.open", lambda f, **kw: (_ for _ in ()).throw(FileNotFoundError)
    )
    with pytest.raises(SystemExit):
        load_config()


# this error also probably because of something im doing wrong
def test_load_config_invalid_utf8(monkeypatch):
    # Set env var to a dummy file.
    monkeypatch.setenv(CONST_PATCH_EVAL_SVC_CONFIG, "dummy_config.json")

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
    monkeypatch.setenv(CONST_PATCH_EVAL_SVC_CONFIG, str(config_file))
    with pytest.raises(SystemExit):
        load_config()


# --------------
# Tests for load_config
# --------------


def test_write_crashes_csv_new_file(tmp_path):
    """
    Test that when the CSV file does not exist, the header is written
    """
    csv_path = tmp_path / "crashes.csv"

    executable_name = "test_exe"
    return_code = 1

    crash_string = "01234abcde"
    crash_encoded = base64.b64encode(crash_string.encode("utf-8")).decode("utf-8")
    crash_detail = CrashDetail(executable_name, crash_encoded, False)
    # Call the function (it should create the file and write the header).
    write_crashes_csv(crash_detail, return_code, csv_path)

    # Read back the file.
    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # head
    # Verify header is present.
    assert lines[0] == "timestamp,crash_detail,return_code,inputFromFile"
    # Each crash line uses the fixed timestamp.
    expected_line1 = (
        f"2025-01-01T12:00:00,{crash_detail.base64_message},{return_code},False"
    )

    assert lines[1] == expected_line1


def test_write_crashes_csv_existing_file_no_header(tmp_path):
    """
    Test that if the CSV file already exists and is non-empty,
    the header is not re-written.
    """
    csv_path = tmp_path / "crashes.csv"
    # Create a file with a header already.
    header = "timestamp,crash_detail,return_code,inputFromFile\n"
    csv_path.write_text(header, encoding="utf-8")

    executable_name = "test_exe"
    # Provide crashes as raw bytes.
    crashes_strings = ["hello", "world"]
    crashes_encoded = [
        base64.b64encode(crash.encode("utf-8")).decode("utf-8")
        for crash in crashes_strings
    ]
    crash_details = [
        CrashDetail(executable_name, crash_encoded, False)
        for crash_encoded in crashes_encoded
    ]

    return_code = 1
    write_crashes_csv(crash_details[0], return_code, str(csv_path))
    write_crashes_csv(crash_details[1], return_code, str(csv_path))

    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()

    # The first line should still be the original header.
    assert lines[0] == "timestamp,crash_detail,return_code,inputFromFile"

    # Compute the expected hex values.
    expected_line1 = f"2025-01-01T12:00:00,{"aGVsbG8="},1,False"
    expected_line2 = f"2025-01-01T12:00:00,{"d29ybGQ="},1,False"
    assert lines[1] == expected_line1
    assert lines[2] == expected_line2


def test_write_crashes_csv_creates_directory(tmp_path):
    """
    Test that the function creates the output directory if it does not exist.
    """
    # Define a CSV path in a subdirectory that does not exist.
    subdir = tmp_path / "nonexistent_dir"
    csv_path = subdir / "crashes.csv"
    executable_name = "test_exe"
    base64_encoded_message = base64.b64encode(b"crash_in_dir").decode("utf-8")
    crash_detail = CrashDetail(executable_name, base64_encoded_message, True)
    return_code = 1
    # Ensure the subdirectory does not exist yet.
    assert not subdir.exists()

    write_crashes_csv(crash_detail, return_code, str(csv_path))

    # Now the directory should have been created.
    assert subdir.exists()

    content = csv_path.read_text(encoding="utf-8")
    lines = content.splitlines()
    expected_line = f"2025-01-01T12:00:00,{crash_detail.base64_message},{return_code},{crash_detail.is_input_from_file}"
    # Header is the first line.
    assert lines[1] == expected_line


def test_write_crashes_csv_logger_called(tmp_path, dummy_logger):
    """
    Test that logger.info is called for each crash.
    """
    csv_path = tmp_path / "crashes.csv"
    executable_name = "test_exe"
    log_crash1_base64 = base64.b64encode(b"log_crash1").decode("utf-8")
    log_crash2_base64 = base64.b64encode(b"log_crash2").decode("utf-8")
    dummy_base64_messages = [log_crash1_base64, log_crash2_base64]
    crash_details = [
        CrashDetail(executable_name, crash, True) for crash in dummy_base64_messages
    ]

    write_crashes_csv(crash_details[0], 1, str(csv_path))
    write_crashes_csv(crash_details[1], 1, str(csv_path))

    # Verify that a log entry was recorded for each crash.
    expected_messages = [f"  - {crash}" for crash in crash_details]
    assert dummy_logger.messages == expected_messages


# --------------
# Tests for log_results
# --------------


def test_log_results_empty_results_dict(tmp_path):
    """
    Test that evaluation.md and evaluation.csv are created when log_results gets an empty results dict,
    and that the header is written for each file and nothing else.
    """
    csv_path = tmp_path / "evaluation.csv"
    md_path = tmp_path / "evaluation.md"

    results = dict()

    log_results(results, tmp_path)
    csv_content = csv_path.read_text()
    csv_lines = csv_content.splitlines()
    md_content = md_path.read_text()
    md_lines = md_content.splitlines()

    assert (
        csv_lines[0]
        == "executable_name,triggers_addressed,triggers_total,success_rate,designation[S,P,F]"
    )
    assert md_lines[0] == "# Results of running patches:"

    assert len(md_lines) == 1
    assert len(csv_lines) == 1


def test_log_results_non_empty_results(tmp_path):
    """
    Test that evaluation.md and evaluation.csv are created when log_results gets a non-empty dict,
    that both the headers and data are written.
    """
    csv_path = tmp_path / "evaluation.csv"
    md_path = tmp_path / "evaluation.md"

    results = dict()
    results["test_exec1"] = dict()
    results["test_exec2"] = dict()
    results["test_exec3"] = dict()
    # this crash should be an F
    results["test_exec1"]["patched_crashes"] = 3
    results["test_exec1"]["total_crashes"] = 4
    # this crash should be a P
    results["test_exec2"]["patched_crashes"] = 4
    results["test_exec2"]["total_crashes"] = 5
    # this crash should be an S
    results["test_exec3"]["patched_crashes"] = 5
    results["test_exec3"]["total_crashes"] = 5

    log_results(results, tmp_path)

    csv_content = csv_path.read_text()
    csv_lines = csv_content.splitlines()

    md_content = md_path.read_text()
    md_lines = md_content.splitlines()

    success_rate_designation = dict()
    success_rate_designation["test_exec1"] = [75.0, "patch failure"]
    success_rate_designation["test_exec2"] = [80.0, "partial potential patch success"]
    success_rate_designation["test_exec3"] = [100.0, "potential patch success"]

    assert (
        csv_lines[0]
        == "executable_name,triggers_addressed,triggers_total,success_rate,designation[S,P,F]"
    )
    assert csv_lines[1] == "test_exec1,3,4,75.0,F"
    assert csv_lines[2] == "test_exec2,4,5,80.0,P"
    assert csv_lines[3] == "test_exec3,5,5,100.0,S"

    assert md_lines[0] == "# Results of running patches:"
    line_num = 1
    for exec_name in results.keys():
        assert md_lines[line_num] == f"### {exec_name}"
        line_num += 1
        assert (
            md_lines[line_num]
            == f"**Patch addresses {results[exec_name]["patched_crashes"]} out of {results[exec_name]["total_crashes"]} trigger conditions.**"
        )
        line_num += 2

        assert (
            md_lines[line_num]
            == f"**Patch is {success_rate_designation[exec_name][0]}% successful: {success_rate_designation[exec_name][1]}.**"
        )
        line_num += 2

    assert (
        md_lines[len(md_lines) - 1]
        == " ### Total success rate of 3 files is 12 / 14, or 85.71%."
    )


def test_log_results_logger_called(tmp_path, dummy_logger):
    """
    Test that logger.info is called for the log_results call.
    """
    csv_path = tmp_path / "evaluation.csv"
    md_path = tmp_path / "evaluation.md"

    results = dict()
    results["test_exec1"] = dict()
    results["test_exec2"] = dict()
    results["test_exec3"] = dict()
    # this crash should be an F
    results["test_exec1"]["patched_crashes"] = 3
    results["test_exec1"]["total_crashes"] = 4
    # this crash should be a P
    results["test_exec2"]["patched_crashes"] = 4
    results["test_exec2"]["total_crashes"] = 5
    # this crash should be an S
    results["test_exec3"]["patched_crashes"] = 5
    results["test_exec3"]["total_crashes"] = 5

    log_results(results, tmp_path)

    expected_messages = [
        f"Creating batched info file {md_path}.",
        f"Creating batched csv file {csv_path}.",
        "Success of evaluation: 85.71%.",
    ]

    # Verify that a log entry was recorded for each crash.

    assert dummy_logger.messages == expected_messages


# --------------
# Tests for create_temp_crash_file
# --------------


def test_create_temp_crash_file_creates_dir(tmp_path):
    subdir = tmp_path / "temp_crash_dir_dne"
    assert not subdir.exists()
    crash_string = "hello_world"
    base64_encoded_message = base64.b64encode(crash_string.encode("utf-8")).decode(
        "utf-8"
    )
    crash_detail = CrashDetail("test_exec", base64_encoded_message, True)

    create_temp_crash_file(crash_detail, subdir)
    assert subdir.exists()


def test_create_temp_crash_file_creates_file(tmp_path):
    subdir = tmp_path / "temp_crash_dir_dne"
    crash_string = "hello_world"
    base64_encoded_message = base64.b64encode(crash_string.encode("utf-8")).decode(
        "utf-8"
    )
    crash_detail = CrashDetail("test_exec", base64_encoded_message, True)

    path = create_temp_crash_file(crash_detail, subdir)

    assert path == f"{subdir}/crash"


# --------------
# Tests for compile_file
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


def test_compile_file_success(monkeypatch):
    exec_dir_path = "/dummy/executables"
    source_code_path = "test.c"
    file_name = "test.c"
    executable_name = "test"

    patch_evaluation_service.config = {
        "compiler_warning_flags": "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong",
        "compile_timeout": 10,
    }

    # Patch subprocess.run to simulate successful compile.
    monkeypatch.setattr(subprocess, "run", dummy_run_success)
    # Patch subprocess.Popen to simulate a process that returns valid output.
    monkeypatch.setattr(subprocess, "Popen", dummy_popen_success)

    # Patch os.path.exists to simulate that the fuzzer_stats file exists.
    def fake_exists(path):
        if path == os.path.join(exec_dir_path, executable_name):
            return True
        return False

    monkeypatch.setattr(os.path, "exists", fake_exists)

    compile_result = compile_file(source_code_path, file_name, exec_dir_path)

    assert compile_result == "test"


def test_compile_file_failure(monkeypatch):
    exec_dir_path = "/dummy/executables"
    source_code_path = "test.c"
    file_name = "test.c"

    patch_evaluation_service.config = {
        "compiler_warning_flags": "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong",
        "compile_timeout": 10,
    }

    # Simulate compile failure.
    def fake_run_fail(*args, **kwargs):
        raise subprocess.CalledProcessError(1, args[0], output="error")

    monkeypatch.setattr(subprocess, "run", fake_run_fail)
    compile_result = compile_file(source_code_path, file_name, exec_dir_path)

    assert compile_result == ""


# --------------
# Tests for run_file
# --------------


def test_run_file_success_stdin(monkeypatch):
    exec_file_path = "/dummy/executables/test"
    executable_name = "test"
    crash_string = "hello_world"
    crash_encoded = base64.b64encode(crash_string.encode("utf-8")).decode("utf-8")
    crash_detail = CrashDetail(executable_name, crash_encoded, False)

    patch_evaluation_service.config = {
        "run_timeout": 10,
    }

    # Patch subprocess.run to simulate successful compile.
    monkeypatch.setattr(subprocess, "run", dummy_run_success)
    # Patch subprocess.Popen to simulate a process that returns valid output.
    monkeypatch.setattr(subprocess, "Popen", dummy_popen_success)

    return_code = run_file(exec_file_path, executable_name, crash_detail)

    assert return_code == 1 or return_code == 0


def test_run_file_failure_stdin(monkeypatch):
    exec_file_path = "/dummy/executables/test"
    executable_name = "test"
    crash_string = "hello_world"
    crash_encoded = base64.b64encode(crash_string.encode("utf-8")).decode("utf-8")
    crash_detail = CrashDetail(executable_name, crash_encoded, False)

    patch_evaluation_service.config = {
        "run_timeout": 10,
    }

    # Simulate compile failure.
    def fake_run_fail(*args, **kwargs):
        raise subprocess.CalledProcessError(127, args[0], output="error")

    monkeypatch.setattr(subprocess, "run", fake_run_fail)

    return_code = run_file(exec_file_path, executable_name, crash_detail)

    assert return_code == -1


def test_run_file_success_file_input(monkeypatch):
    exec_file_path = "/dummy/executables/test"
    executable_name = "test"
    crash_string = "hello_world"
    crash_encoded = base64.b64encode(crash_string.encode("utf-8")).decode("utf-8")
    crash_detail = CrashDetail(executable_name, crash_encoded, True)

    patch_evaluation_service.config = {
        "run_timeout": 10,
    }

    # Patch subprocess.run to simulate successful compile.
    monkeypatch.setattr(subprocess, "run", dummy_run_success)
    # Patch subprocess.Popen to simulate a process that returns valid output.
    monkeypatch.setattr(subprocess, "Popen", dummy_popen_success)

    return_code = run_file(exec_file_path, executable_name, crash_detail)

    assert return_code == 1 or return_code == 0


def test_run_file_failure_file_input(monkeypatch):
    exec_file_path = "/dummy/executables/test"
    executable_name = "test"
    crash_string = "hello_world"
    crash_encoded = base64.b64encode(crash_string.encode("utf-8")).decode("utf-8")
    crash_detail = CrashDetail(executable_name, crash_encoded, True)

    patch_evaluation_service.config = {
        "run_timeout": 10,
    }

    # Simulate compile failure.
    def fake_run_fail(*args, **kwargs):
        raise subprocess.CalledProcessError(127, args[0], output="error")

    monkeypatch.setattr(subprocess, "run", fake_run_fail)

    return_code = run_file(exec_file_path, executable_name, crash_detail)

    assert return_code == -1
