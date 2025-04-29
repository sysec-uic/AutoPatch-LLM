import asyncio
import base64
import json
import logging
import os
import subprocess
from io import StringIO
from typing import Dict
from unittest import mock

import paho.mqtt.client as mqtt_client
import patch_evaluation_service
import pytest
from autopatchdatatypes import CrashDetail
from patch_eval_config import PatchEvalConfig

# Import the functions and globals
from patch_evaluation_service import (
    compile_file,
    map_cloud_event_as_crash_detail,
    on_consume_crash_detail,
    prep_programs_for_evaluation,
    run_file_async,
    write_crashes_csv,
)


class DummyProcess:
    def __init__(self, returncode=0, stdout=b"output", stderr=b"error"):
        self.returncode = returncode
        self._stdout = stdout
        self._stderr = stderr

    async def communicate(self, input=None):
        return (self._stdout, self._stderr)

    def kill(self):
        self.returncode = -1


def dummy_config_content() -> Dict:
    return {
        "appname": "autopatch.patch-evaluation-service",
        "version": "0.8.0-alpha",
        "logging_config": "/workspace/AutoPatch-LLM/src/patch-evaluation-service/config/dev-logging-config.json",
        "patch_eval_results_full_path": "/workspace/AutoPatch-LLM/src/patch-evaluation-service/data",
        "patched_codes_path": "/workspace/AutoPatch-LLM/src/patch-evaluation-service/patched_codes",
        "executables_full_path": "/workspace/AutoPatch-LLM/src/patch-evaluation-service/bin/executables",
        "compiler_tool_full_path": "/usr/bin/gcc",
        "compiler_warning_flags": "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong",
        "compiler_feature_flags": "-O1 -g -o",
        "compile_timeout": 5,
        "run_timeout": 5,
        "message_broker_host": "mosquitto",
        "message_broker_port": 1883,
        "autopatch_crash_detail_input_topic": "autopatch/crash_detail",
        "autopatch_patch_response_input_topic": "autopatch/patch_response",
        "make_tool_full_path": "/usr/bin/make",
    }


def dummy_PatchEvalConfig() -> PatchEvalConfig:
    dummy_config: Dict = dummy_config_content()
    return PatchEvalConfig(**dummy_config)


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
        patch_evaluation_service, "MessageBrokerClient", DummyMessageBrokerClient
    )


# A dummy logger to capture logger calls.
class DummyLogger(logging.Logger):
    def __init__(self):
        super().__init__(name="dummy")
        self.messages = []
        self.level = logging.DEBUG

    def info(self, msg):
        self.messages.append(msg)

    def debug(self, msg):  # noqa: A003
        self.messages.append(msg)

    def error(self, msg):
        self.messages.append(msg)

    def log(self, level, msg, *args, **kwargs):  # noqa: A003
        self.messages.append(msg)


@pytest.fixture(autouse=True)
def mock_logger(monkeypatch):
    logger = DummyLogger()
    monkeypatch.setattr("patch_evaluation_service.logger", logger)
    return logger


class DummyResult:
    def __init__(self, stdout: str = "", stderr: str = ""):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = 0


def test_compile_success(tmp_path, monkeypatch, mock_logger):
    source = tmp_path / "hello.c"
    source.write_text("int main() { return 0; }")
    output_dir = str(tmp_path)
    exec_name = "hello"
    exec_path = os.path.join(output_dir, exec_name)

    # Fake subprocess.run returning a successful result
    dummy = DummyResult(stdout="built", stderr="")

    def fake_run(cmd, stderr, stdout, universal_newlines, timeout, shell):
        expected = f"gcc {source} -Wall -O2 {exec_path}"
        assert cmd == [expected]
        return dummy

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(os.path, "exists", lambda p: p == exec_path)

    result = compile_file(
        source_file_full_path=str(source),
        output_dir_path=output_dir,
        compiler_tool_full_patch="gcc",
        compiler_warning_flags="-Wall",
        compiler_feature_flags="-O2",
        compiler_timeout=10,
    )

    assert result == exec_path
    # Check logged messages
    assert any("Compiled with command" in m for m in mock_logger.messages)
    assert any(
        f"stderr of the compile: {dummy.stderr}" in m for m in mock_logger.messages
    )
    assert any(f"Executable {exec_path} exists." in m for m in mock_logger.messages)


def test_compile_no_executable(tmp_path, monkeypatch, mock_logger):
    source = tmp_path / "prog.c"
    output_dir = str(tmp_path)

    dummy = DummyResult(stdout="", stderr="some error")
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: dummy)
    monkeypatch.setattr(os.path, "exists", lambda p: False)

    result = compile_file(
        source_file_full_path=str(source),
        output_dir_path=output_dir,
        compiler_tool_full_patch="gcc",
        compiler_warning_flags="-Werror",
        compiler_feature_flags="-O3",
        compiler_timeout=5,
    )

    assert result == ""
    assert any("Failed to compile" in m for m in mock_logger.messages)


def test_compile_timeout_exception(tmp_path, monkeypatch, mock_logger):
    source = tmp_path / "timeout.c"
    output_dir = str(tmp_path)

    def fake_run(*args, **kwargs):
        raise subprocess.TimeoutExpired(cmd="gcc", timeout=2)

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(os.path, "exists", lambda p: False)

    result = compile_file(
        source_file_full_path=str(source),
        output_dir_path=output_dir,
        compiler_tool_full_patch="gcc",
        compiler_warning_flags="",
        compiler_feature_flags="",
        compiler_timeout=2,
    )

    assert result == ""
    assert any("An error occurred while compiling" in m for m in mock_logger.messages)


def test_source_basename_edge_cases(tmp_path, monkeypatch, mock_logger):
    source = tmp_path / "Makefile"
    output_dir = str(tmp_path)
    exec_path = os.path.join(output_dir, "Makefile")

    dummy = DummyResult()
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: dummy)
    monkeypatch.setattr(os.path, "exists", lambda p: p == exec_path)

    result = compile_file(
        source_file_full_path=str(source),
        output_dir_path=output_dir,
        compiler_tool_full_patch="cc",
        compiler_warning_flags="",
        compiler_feature_flags="",
        compiler_timeout=1,
    )

    assert result == exec_path


def test_multiple_dots_in_filename(tmp_path, monkeypatch, mock_logger):
    source = tmp_path / "my.cool.program.c"
    output_dir = str(tmp_path)
    exec_path = os.path.join(output_dir, "my")

    dummy = DummyResult()
    monkeypatch.setattr(subprocess, "run", lambda *args, **kwargs: dummy)
    monkeypatch.setattr(os.path, "exists", lambda p: p == exec_path)

    result = compile_file(
        source_file_full_path=str(source),
        output_dir_path=output_dir,
        compiler_tool_full_patch="cc",
        compiler_warning_flags="-W",
        compiler_feature_flags="-std=c11",
        compiler_timeout=3,
    )

    assert result == exec_path


# --- Tests for run_file_async ---


@pytest.mark.asyncio
async def test_run_file_byte_input_async_success(monkeypatch):
    # Assemble

    # Simulate successful execution for byte input on stdin
    dummy_proc = DummyProcess(returncode=0, stdout=b"success", stderr=b"")

    async def fake_create_subprocess_exec(*args, **kwargs):
        return dummy_proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    # Create a dummy CrashDetail with some base64-encoded crash message.
    message = "dummy crash"
    encoded = base64.b64encode(message.encode()).decode()
    crash_detail = CrashDetail(
        executable_name="dummy_exe", base64_message=encoded, is_input_from_file=True
    )

    crash_detail.is_input_from_file = False

    # Act
    result = await run_file_async(
        "dummy_path", "dummy_exe", crash_detail, "", timeout=5
    )

    # Assert
    assert result == 0


@pytest.mark.asyncio
async def test_run_file_file_input_async_success(monkeypatch):
    # Assemble
    # Simulate successful execution for both file input
    dummy_proc = DummyProcess(returncode=0, stdout=b"success", stderr=b"")

    async def fake_create_subprocess_exec(*args, **kwargs):
        return dummy_proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    # Create a dummy CrashDetail with some base64-encoded crash message.
    message = "dummy crash"
    encoded = base64.b64encode(message.encode()).decode()
    crash_detail = CrashDetail(
        executable_name="dummy_exe", base64_message=encoded, is_input_from_file=True
    )

    # Act
    result = await run_file_async(
        "dummy_path", "dummy_exe", crash_detail, "dummy_temp_file", timeout=5
    )

    # Assert
    assert result == 0


@pytest.mark.asyncio
@pytest.mark.filterwarnings("ignore::pytest.PytestUnhandledThreadExceptionWarning")
async def test_run_file_async_timeout(monkeypatch):
    # Assemble
    # Create a dummy process that delays its response to trigger a timeout.
    class DummyProcessTimeout:
        def __init__(self):
            self.returncode = None

        async def communicate(self, input=None):
            await asyncio.sleep(2)
            return (b"", b"")

        def kill(self):
            self.returncode = -1

    async def fake_create_subprocess_exec(*args, **kwargs):
        return DummyProcessTimeout()

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    message = "dummy crash"
    encoded = base64.b64encode(message.encode()).decode()
    crash_detail = CrashDetail(
        executable_name="dummy_exe", base64_message=encoded, is_input_from_file=False
    )

    # Act
    result = await run_file_async(
        "dummy_path", "dummy_exe", crash_detail, "", timeout=1
    )

    # Assert
    assert result == -1


@pytest.mark.asyncio
async def test_run_file_async_exception(monkeypatch):
    # Assemble
    async def fake_create_subprocess_exec(*args, **kwargs):
        raise Exception("test exception")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    message = "dummy crash"
    encoded = base64.b64encode(message.encode()).decode()
    crash_detail = CrashDetail(
        executable_name="dummy_exe", base64_message=encoded, is_input_from_file=False
    )

    # Act
    result = await run_file_async(
        "dummy_path", "dummy_exe", crash_detail, "", timeout=5
    )

    # Assert
    assert result == -1


@pytest.mark.asyncio
async def test_run_file_async_signal(monkeypatch):
    # Assemble
    # Simulate a process with return code 130, which should yield a signal code 2 (i.e. 130-128).
    dummy_proc = DummyProcess(returncode=130, stdout=b"output", stderr=b"error")

    async def fake_create_subprocess_exec(*args, **kwargs):
        return dummy_proc

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    message = "dummy crash"
    encoded = base64.b64encode(message.encode()).decode()
    crash_detail = CrashDetail(
        executable_name="dummy_exe", base64_message=encoded, is_input_from_file=False
    )

    # Act
    result = await run_file_async(
        "dummy_path", "dummy_exe", crash_detail, "", timeout=5
    )

    # Assert
    assert result == 2


# # --- Tests for write_crashes_csv and log_crash_information ---


@pytest.fixture(autouse=True)
def fixed_timestamp(monkeypatch):
    # Freeze timestamp for predictable output
    monkeypatch.setattr(
        "patch_evaluation_service.get_current_timestamp", lambda: "2025-04-23T00:00:00Z"
    )
    return None


class DummyFile(StringIO):
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        pass


@pytest.fixture(autouse=True)
def skip_makedirs(monkeypatch):
    # Avoid creating actual directories
    monkeypatch.setattr(os, "makedirs", lambda path, exist_ok: None)
    return None


@pytest.mark.parametrize(
    "exists,size,header_expected",
    [
        (False, 0, True),  # File missing or empty -> header
        (True, 100, False),  # File exists and non-empty -> no header
    ],
)
def test_write_crashes_csv(
    tmp_path, monkeypatch, mock_logger, exists, size, header_expected
):

    _base64_message = base64.b64encode("test message".encode()).decode()

    crash = CrashDetail(
        executable_name="testprog",
        base64_message=_base64_message,
        is_input_from_file=True,
    )
    patch_str = "PATCHDATA"
    return_code = 42
    llm_name = "gpt4"
    llm_flavor = "standard"
    llm_version = "1.0"

    # CSV path under tmp
    csv_path = tmp_path / "out" / "crashes.csv"

    # Simulate file existence and size
    monkeypatch.setattr(os.path, "exists", lambda p: exists)
    monkeypatch.setattr(os.path, "getsize", lambda p: size)

    # Capture writes to a dummy file
    dummy_file = DummyFile()
    monkeypatch.setattr(
        "builtins.open",  # the full import path
        lambda path, mode="r", encoding=None: dummy_file,
        raising=True,
    )

    # Invoke function
    write_crashes_csv(
        crash_detail=crash,
        patch_base64_str=patch_str,
        return_code=return_code,
        csv_path=str(csv_path),
        llm_name=llm_name,
        llm_flavor=llm_flavor,
        llm_version=llm_version,
    )

    contents = dummy_file.getvalue().splitlines(keepends=True)

    # Check header line
    header_line = (
        "timestamp,"
        "program_name,"
        "crash_detail,"
        "return_code,"
        "isInputFromFile,"
        "llm_name,"
        "llm_flavor,"
        "llm_version,"
        "patch_base64_str\n"
    )

    if header_expected:
        assert contents[0] == header_line
        data_line = contents[1]
    else:
        assert not contents[0].startswith("timestamp")
        data_line = contents[0]

    # Verify data line structure
    assert data_line.startswith(
        f"2025-04-23T00:00:00Z,testprog,{_base64_message},42,True,gpt4,standard,1.0"
    )
    assert data_line.strip().endswith(patch_str)


# # --- Test for map_cloud_event_as_crash_detail ---


def test_map_cloud_event_as_crash_detail():
    # Assemble
    data = {
        "data": {
            "executable_name": "dummy_exe",
            "crash_detail_base64": base64.b64encode("crash".encode()).decode(),
            "is_input_from_file": True,
        }
    }
    cloud_event_str = json.dumps(data)

    # Act
    crash_detail = asyncio.run(map_cloud_event_as_crash_detail(cloud_event_str))

    # Assert
    assert crash_detail.executable_name == "dummy_exe"
    assert crash_detail.is_input_from_file is True
    decoded = base64.b64decode(crash_detail.base64_message).decode("utf-8")
    assert decoded == "crash"


# # --- Test for load_config ---


def test_load_config(monkeypatch):
    def fake_load_config_as_json(path, logger):
        return {
            "appname": "autopatch.patch-evaluation-service",
            "version": "0.8.0-beta",
            "input_codebase_full_path": "/dummy/input_codebase",
            "logging_config": "/dummy/logging-config.json",
            "patch_eval_results_full_path": "/dummy/data",
            "patched_codes_path": "/dummy/patched_codes",
            "executables_full_path": "/dummy/executables",
            "compiler_tool_full_path": "/dummy/bin/gcc",
            "compiler_warning_flags": "-Wall -Wextra -Wformat -Wshift-overflow -Wcast-align -Wstrict-overflow -fstack-protector-strong",
            "compiler_feature_flags": "-O1 -g -o",
            "compile_timeout": 10,
            "run_timeout": 20,
            "message_broker_host": "mosquitto",
            "message_broker_port": 1883,
            "autopatch_crash_detail_input_topic": "autopatch/crash_detail",
            "autopatch_patch_response_input_topic": "autopatch/patch_response",
            "make_tool_full_path": "/usr/bin/make",
            "model_names": ["mistral-small-3.1-24b-instruct"],
        }

    # Assemble
    monkeypatch.setattr(
        patch_evaluation_service, "load_config_as_json", fake_load_config_as_json
    )
    dummy_logger = logging.getLogger("dummy")

    # Act
    config_obj = patch_evaluation_service.load_config("dummy_path", dummy_logger)

    # Assert
    assert isinstance(config_obj, PatchEvalConfig)
    assert config_obj.appname == "autopatch.patch-evaluation-service"


# # --- Test for on_consume_crash_detail ---


# Dummy queue to capture put_nowait calls
class DummyQueue:
    def __init__(self):
        self.items = []

    def put_nowait(self, item):
        self.items.append(item)


# Dummy event loop to capture and invoke scheduled calls
class DummyEventLoop:
    def __init__(self):
        self.calls = []

    def call_soon_threadsafe(self, callback, *args):
        # record the callback and args
        self.calls.append((callback, args))
        # simulate immediate invocation
        callback(*args)


@pytest.mark.asyncio
async def test_prep_programs_for_evaluation(monkeypatch, tmp_path):
    # Assemble
    def fake_compile_file(
        file_path,
        file_name,
        executable_path,
        compiler_tool_full_path,
        compiler_warning_flags,
        compiler_feature_flags,
        compile_timeout,
    ):
        # For testing, simply return the file name without extension.
        return file_name.split(".")[0]

    # Create a dummy patched codes directory with two files.
    patched_codes_dir = tmp_path / "patches"
    patched_codes_dir.mkdir()
    (patched_codes_dir / "file1.c").write_text("dummy")
    (patched_codes_dir / "file2.c").write_text("dummy")
    executables_dir = tmp_path / "executables"
    executables_dir.mkdir()

    monkeypatch.setattr("patch_evaluation_service.compile_file", fake_compile_file)

    # Act

    executables, results_dict = await prep_programs_for_evaluation(
        str(executables_dir),
        str(patched_codes_dir),
        "dummy_compiler",
        "-Wall",
        "-std=c99",
        5,
        "dummy_make",
    )

    # Assert
    assert "file1" in executables
    assert "file2" in executables
    assert results_dict["file1"]["total_crashes"] == 0
    assert results_dict["file1"]["patched_crashes"] == 0


@pytest.fixture
def dummy_queue(monkeypatch):
    dq = DummyQueue()
    monkeypatch.setattr(
        patch_evaluation_service, "async_crash_details_cloud_events_queue", dq
    )
    return dq


@pytest.fixture
def dummy_event_loop(monkeypatch):
    de = DummyEventLoop()
    monkeypatch.setattr(patch_evaluation_service, "event_loop", de, raising=False)
    return de


def test_normal_scheduling(dummy_event_loop, dummy_queue, mock_logger):
    sample = '{"foo": "bar"}'
    on_consume_crash_detail(sample)

    # Logs
    assert any(
        "Received crash detail from message broker." in msg
        for msg in mock_logger.messages
    )
    assert any(
        f"Received crash detail: {sample}" in msg for msg in mock_logger.messages
    )

    # Event loop scheduled exactly one call
    assert len(dummy_event_loop.calls) == 1
    _, args = dummy_event_loop.calls[0]
    # Should have scheduled the queue put with the right argument
    assert args == (sample,)

    # Queue received the sample
    assert dummy_queue.items == [sample]


@pytest.mark.parametrize("input_str", ["", "   ", "こんにちは", "🙂🚀"])
def test_various_strings(dummy_event_loop, dummy_queue, mock_logger, input_str):
    # Should schedule and store any string, even empty or unicode
    on_consume_crash_detail(input_str)
    assert dummy_queue.items[-1] == input_str
    assert any(
        input_str in msg
        for msg in mock_logger.messages
        if "Received crash detail" in msg
    )


def test_exception_propagates(monkeypatch):
    # If scheduling fails, exception should propagate
    def bad_call(callback, *args):
        raise RuntimeError("boom")

    # patch only the event_loop.call_soon_threadsafe
    monkeypatch.setattr(
        patch_evaluation_service,
        "event_loop",
        type("E", (), {"call_soon_threadsafe": bad_call})(),
        raising=False,
    )
    with pytest.raises(RuntimeError):
        on_consume_crash_detail("data")
