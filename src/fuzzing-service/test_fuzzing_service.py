import json
import logging
import os
import subprocess
import sys
import tempfile

import pytest

# Import the functions and constants from the module.
# (Assuming your code is in fuzzing_service.py)
from fuzzing_service import timeout  # so that we know what timeout is used
from fuzzing_service import (
    CONST_FUZZ_SVC_CONFIG,
    extract_crashes,
    init_logging,
    load_config,
    main,
    run_fuzzer,
    run_sanitizer,
)

#########################################
# Tests for init_logging
#########################################


def test_init_logging_valid(tmp_path, caplog):
    # Create a valid logging configuration file.
    config_data = {
        "version": 1,
        "disable_existing_loggers": False,
        "formatters": {"default": {"format": "%(levelname)s:%(name)s:%(message)s"}},
        "handlers": {
            "console": {
                "class": "logging.StreamHandler",
                "formatter": "default",
                "level": "DEBUG",
            }
        },
        "loggers": {
            "test_app": {
                "handlers": ["console"],
                "level": "DEBUG",
            }
        },
    }
    config_file = tmp_path / "log_config.json"
    config_file.write_text(json.dumps(config_data))

    # Call init_logging with a valid file.
    logger = init_logging(str(config_file), "test_app")

    # The logger should have been configured and should log the init message.
    with caplog.at_level(logging.INFO):
        logger.info("Test message")
    assert "Logger initialized successfully." in caplog.text
    # Also check that the logger level is as set in the config (DEBUG)
    assert logger.getEffectiveLevel() == logging.DEBUG


def test_init_logging_missing_file(tmp_path, capsys):
    # Use a non-existent file
    fake_path = str(tmp_path / "nonexistent.json")
    logger = init_logging(fake_path, "test_app")
    # The function prints an error message and falls back to basic config.
    captured = capsys.readouterr().out
    assert "not found" in captured
    # BasicConfig uses INFO by default.
    assert logger.getEffectiveLevel() == logging.INFO


def test_init_logging_invalid_json(tmp_path, capsys):
    # Create a file with invalid JSON.
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("this is not json")
    logger = init_logging(str(bad_file), "test_app")
    captured = capsys.readouterr().out
    assert "Error decoding JSON" in captured or "Expecting value" in captured
    assert logger.getEffectiveLevel() == logging.INFO


#########################################
# Tests for load_config
#########################################


def test_load_config_env_not_set(monkeypatch, capsys):
    # Ensure that the environment variable is not set.
    monkeypatch.delenv(CONST_FUZZ_SVC_CONFIG, raising=False)
    with pytest.raises(SystemExit) as e:
        load_config()
    assert e.value.code == 1
    captured = capsys.readouterr().out
    assert "FUZZ_SVC_CONFIG" in captured


def test_load_config_file_not_found(monkeypatch, tmp_path, capsys):
    fake_config_path = str(tmp_path / "nonexistent_config.json")
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, fake_config_path)
    with pytest.raises(SystemExit) as e:
        load_config()
    assert e.value.code == 1
    captured = capsys.readouterr().out
    assert "was not found" in captured


def test_load_config_invalid_json(monkeypatch, tmp_path, capsys):
    config_file = tmp_path / "bad_config.json"
    config_file.write_text("not a valid json")
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, str(config_file))
    with pytest.raises(SystemExit) as e:
        load_config()
    assert e.value.code == 1
    captured = capsys.readouterr().out
    assert "contains invalid JSON" in captured


def test_load_config_unicode_error(monkeypatch, tmp_path, capsys):
    # Write bytes that are invalid UTF-8.
    config_file = tmp_path / "bad_utf8.json"
    with open(config_file, "wb") as f:
        f.write(b"\xff\xfe\xfd")
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, str(config_file))
    with pytest.raises(SystemExit) as e:
        load_config()
    assert e.value.code == 1
    captured = capsys.readouterr().out
    assert "not a valid UTF-8" in captured


def test_load_config_success(monkeypatch, tmp_path):
    # Prepare a valid configuration dictionary.
    config_data = {
        "version": "1.0",
        "appname": "test_app",
        "logging_config": str(tmp_path / "log_config.json"),
        "fuzz_svc_input_codebase_path": str(tmp_path / "codebase"),
        "compiled_binary_executables_output_path": str(tmp_path / "compiled"),
        "compiler_tool_full_path": "/usr/bin/gcc",
        "fuzzer_tool_name": "afl-fuzz",
        "fuzzer_tool_version": "2.52b",
        "afl_tool_full_path": "/usr/bin/afl-fuzz",
        "afl_tool_seed_input_path": str(tmp_path / "seed"),
        "afl_tool_output_path": str(tmp_path / "fuzz_out"),
        "afl_tool_compiled_binary_executables_output_path": str(
            tmp_path / "afl_compiled"
        ),
        "afl_compiler_tool_full_path": "/usr/bin/afl-clang",
        "mqtt_host": "localhost",
        "mqtt_port": 1833,
        "debug": False,
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config_data))
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, str(config_file))

    loaded = load_config()
    # Check that all keys are present.
    for key in config_data:
        assert key in loaded
    # Optionally check a few values
    assert loaded["appname"] == "test_app"


#########################################
# Tests for run_sanitizer
#########################################


class DummyCompletedProcess:
    def __init__(self, returncode=0, stdout="", stderr=""):
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = stderr


def dummy_run_success(*args, **kwargs):
    return DummyCompletedProcess()


def dummy_run_failure(*args, **kwargs):
    raise Exception("compile error")


def test_run_sanitizer_success(monkeypatch, tmp_path):
    # Monkeypatch subprocess.run to always succeed.
    monkeypatch.setattr(subprocess, "run", dummy_run_success)
    # Set dummy global logger if needed.
    dummy_prog = "dummy.c"
    dummy_out_dir = str(tmp_path / "compiled")
    os.makedirs(dummy_out_dir, exist_ok=True)
    # run_sanitizer returns True on success.
    result = run_sanitizer(dummy_prog, dummy_out_dir, "dummy_exe")
    assert result is True


def test_run_sanitizer_failure(monkeypatch):
    monkeypatch.setattr(subprocess, "run", dummy_run_failure)
    result = run_sanitizer("dummy.c", "/dummy/out", "dummy_exe")
    # When an exception is raised, run_sanitizer returns a tuple.
    assert isinstance(result, tuple)
    success, err_msg = result
    assert not success
    assert "compile error" in err_msg


#########################################
# Tests for run_fuzzer
#########################################


# We create a dummy subprocess.run that inspects the command string to decide what to do.
class FuzzerRunHelper:
    def __init__(
        self, raise_on_fuzz=False, raise_on_compile=False, raise_on_timeout=False
    ):
        self.raise_on_compile = raise_on_compile
        self.raise_on_fuzz = raise_on_fuzz
        self.raise_on_timeout = raise_on_timeout
        self.call_count = 0  # to differentiate between compile and fuzz runs

    def dummy_run(self, command, **kwargs):
        self.call_count += 1
        # First call is for compile, second is for fuzz run.
        if self.call_count == 1:
            if self.raise_on_compile:
                raise subprocess.CalledProcessError(returncode=1, cmd=command)
            return DummyCompletedProcess(stdout="compiled", stderr="")
        elif self.call_count == 2:
            if self.raise_on_fuzz:
                raise subprocess.CalledProcessError(returncode=1, cmd=command)
            if self.raise_on_timeout:
                raise subprocess.TimeoutExpired(cmd=command, timeout=timeout)
            return DummyCompletedProcess(stdout="fuzzed", stderr="")
        else:
            return DummyCompletedProcess()


def fake_os_path_exists(path):
    # For run_fuzzer we check for the file f"{fuzzer_output_path}/{executable_name}/fuzzer_stats"
    if "fuzzer_stats" in path:
        return True
    return False


@pytest.mark.parametrize("input_from_file", [True, False])
def test_run_fuzzer_success(monkeypatch, tmp_path, input_from_file):
    # Create a dummy helper that does not raise exceptions.
    helper = FuzzerRunHelper()
    monkeypatch.setattr(subprocess, "run", helper.dummy_run)
    monkeypatch.setattr(os.path, "exists", fake_os_path_exists)
    # Provide dummy parameters.
    ret = run_fuzzer(
        executable_name="dummy",
        codebase_path=str(tmp_path / "codebase"),
        program_path="dummy.c",
        executables_afl_path=str(tmp_path / "afl_compiled"),
        fuzzer_compiler_full_path="/dummy/afl-clang",
        fuzzer_full_path="/dummy/afl-fuzz",
        fuzzer_seed_input_path="/dummy/seed",
        fuzzer_output_path="/dummy/fuzz_out",
        timeout_fuzzer=1000,
        inputFromFile=input_from_file,
        isCodebase=True,
    )
    assert ret is True


def test_run_fuzzer_compile_failure(monkeypatch, tmp_path):
    helper = FuzzerRunHelper(raise_on_compile=True)
    monkeypatch.setattr(subprocess, "run", helper.dummy_run)
    ret = run_fuzzer(
        executable_name="dummy",
        codebase_path=str(tmp_path / "codebase"),
        program_path="dummy.c",
        executables_afl_path=str(tmp_path / "afl_compiled"),
        fuzzer_compiler_full_path="/dummy/afl-clang",
        fuzzer_full_path="/dummy/afl-fuzz",
        fuzzer_seed_input_path="/dummy/seed",
        fuzzer_output_path="/dummy/fuzz_out",
        timeout_fuzzer=1000,
        inputFromFile=True,
        isCodebase=True,
    )
    assert ret is False


def test_run_fuzzer_fuzz_run_failure(monkeypatch, tmp_path):
    helper = FuzzerRunHelper(raise_on_fuzz=True)
    monkeypatch.setattr(subprocess, "run", helper.dummy_run)
    ret = run_fuzzer(
        executable_name="dummy",
        codebase_path=str(tmp_path / "codebase"),
        program_path="dummy.c",
        executables_afl_path=str(tmp_path / "afl_compiled"),
        fuzzer_compiler_full_path="/dummy/afl-clang",
        fuzzer_full_path="/dummy/afl-fuzz",
        fuzzer_seed_input_path="/dummy/seed",
        fuzzer_output_path="/dummy/fuzz_out",
        timeout_fuzzer=1000,
        inputFromFile=False,
        isCodebase=True,
    )
    assert ret is False


def test_run_fuzzer_timeout(monkeypatch, tmp_path):
    helper = FuzzerRunHelper(raise_on_timeout=True)
    monkeypatch.setattr(subprocess, "run", helper.dummy_run)
    monkeypatch.setattr(os.path, "exists", fake_os_path_exists)
    # Even though the fuzz run times out, the fuzzer may be considered to have started
    ret = run_fuzzer(
        executable_name="dummy",
        codebase_path=str(tmp_path / "codebase"),
        program_path="dummy.c",
        executables_afl_path=str(tmp_path / "afl_compiled"),
        fuzzer_compiler_full_path="/dummy/afl-clang",
        fuzzer_full_path="/dummy/afl-fuzz",
        fuzzer_seed_input_path="/dummy/seed",
        fuzzer_output_path="/dummy/fuzz_out",
        timeout_fuzzer=1000,
        inputFromFile=True,
        isCodebase=True,
    )
    # Since os.path.exists returns True for fuzzer_stats, the function returns True.
    assert ret is True


#########################################
# Tests for extract_crashes
#########################################


def test_extract_crashes_input_from_file(monkeypatch, tmp_path):
    # Create a temporary directory structure:
    # <fuzzer_output_path>/dummy/crashes/
    crash_dir = tmp_path / "fuzz_out" / "dummy" / "crashes"
    crash_dir.mkdir(parents=True)
    # Create a README.txt (should be skipped) and a crash file.
    (crash_dir / "README.txt").write_text("This is a README")
    crash_file = crash_dir / "crash1"
    crash_file.write_text("crash content", encoding="ISO-8859-1")

    # Monkeypatch subprocess.run so that the iconv conversion “succeeds”
    def dummy_iconv(*args, **kwargs):
        return DummyCompletedProcess(stdout="converted", stderr="")

    monkeypatch.setattr(subprocess, "run", dummy_iconv)
    # Monkeypatch os.replace to do nothing (or simply pass through)
    monkeypatch.setattr(os, "replace", lambda src, dst: None)

    crashes = extract_crashes(str(tmp_path / "fuzz_out"), "dummy", inputFromFile=True)
    # We expect one crash file (README.txt skipped)
    assert len(crashes) == 1
    # The returned item should be the crash file’s path (as a string)
    assert isinstance(crashes[0], str)
    # Optionally, check that the path ends with "crash1"
    assert crashes[0].endswith("crash1")


def test_extract_crashes_not_input_from_file(tmp_path):
    # Create temporary directory structure with a crash file containing binary data.
    crash_dir = tmp_path / "fuzz_out" / "dummy" / "crashes"
    crash_dir.mkdir(parents=True)
    crash_file = crash_dir / "crash_binary"
    crash_file.write_bytes(b"\x00\x01\x02")

    crashes = extract_crashes(str(tmp_path / "fuzz_out"), "dummy", inputFromFile=False)
    # Should return a list with one element containing the binary content.
    assert len(crashes) == 1
    assert crashes[0] == b"\x00\x01\x02"


def test_extract_crashes_no_directory(tmp_path, caplog):
    # Call extract_crashes with a non-existent crashes directory.
    non_exist_dir = str(tmp_path / "fuzz_out")
    crashes = extract_crashes(non_exist_dir, "dummy", inputFromFile=True)
    # Should be empty.
    assert crashes == []
    # And an error should be logged.
    assert "No crashes directory found" in caplog.text


#########################################
# Test for main (integration-style)
#########################################


def test_main(monkeypatch, tmp_path, caplog):
    """
    Test the main function by preparing a temporary configuration file,
    a dummy codebase directory with one .c file and overriding functions that would run external commands.
    """
    # Create dummy directories for the config keys.
    codebase_dir = tmp_path / "codebase"
    codebase_dir.mkdir()
    compiled_dir = tmp_path / "compiled"
    compiled_dir.mkdir()
    afl_compiled_dir = tmp_path / "afl_compiled"
    afl_compiled_dir.mkdir()
    seed_dir = tmp_path / "seed"
    seed_dir.mkdir()
    fuzz_out_dir = tmp_path / "fuzz_out"
    fuzz_out_dir.mkdir()

    # Create a dummy .c file in the codebase directory.
    dummy_c = codebase_dir / "dummy.c"
    dummy_c.write_text("int main(){ return 0; }")

    # Create a valid logging configuration file.
    log_config = tmp_path / "log_config.json"
    log_config.write_text(
        json.dumps(
            {
                "version": 1,
                "disable_existing_loggers": False,
                "formatters": {"default": {"format": "%(levelname)s:%(message)s"}},
                "handlers": {
                    "console": {
                        "class": "logging.StreamHandler",
                        "formatter": "default",
                        "level": "DEBUG",
                    }
                },
                "loggers": {
                    "test_app": {
                        "handlers": ["console"],
                        "level": "DEBUG",
                    }
                },
            }
        )
    )

    # Prepare a full config dictionary.
    config_data = {
        "version": "1.0",
        "appname": "test_app",
        "logging_config": str(log_config),
        "fuzz_svc_input_codebase_path": str(codebase_dir),
        "compiled_binary_executables_output_path": str(compiled_dir),
        "compiler_tool_full_path": "/usr/bin/gcc",
        "fuzzer_tool_name": "afl-fuzz",
        "fuzzer_tool_version": "2.52b",
        "afl_tool_full_path": "/usr/bin/afl-fuzz",
        "afl_tool_seed_input_path": str(seed_dir),
        "afl_tool_output_path": str(fuzz_out_dir),
        "afl_tool_compiled_binary_executables_output_path": str(afl_compiled_dir),
        "afl_compiler_tool_full_path": "/usr/bin/afl-clang",
        "mqtt_host": "localhost",
        "mqtt_port": 1833,
        "debug": False,
    }
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps(config_data))
    monkeypatch.setenv(CONST_FUZZ_SVC_CONFIG, str(config_file))

    # Override run_sanitizer, run_fuzzer, extract_crashes to avoid running real subprocesses.
    monkeypatch.setattr(
        "fuzzing_service.run_sanitizer", lambda prog, out_dir, name: True
    )
    monkeypatch.setattr("fuzzing_service.run_fuzzer", lambda *args, **kwargs: True)
    monkeypatch.setattr("fuzzing_service.extract_crashes", lambda *args, **kwargs: [])

    # Run main()
    main()

    # Check that log messages were written (for example, that processing of dummy.c was mentioned)
    assert "Processing:" in caplog.text
    assert "ASan compilation succeeded" in caplog.text
    assert "Fuzzer started" in caplog.text
    assert "No crashes found" in caplog.text
