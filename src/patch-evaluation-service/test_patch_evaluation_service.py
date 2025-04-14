import asyncio
import base64
import json
import logging
import os
import subprocess
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
    prep_executables_for_evaluation,
    process_crash_detail,
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


def dummy_PatchEvalConfig() -> PatchEvalConfig:
    dummy_config = {
        "version": "0.4.1-alpha",
        "appname": "autopatch.patch-evaluation-service",
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
    }

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


# # --- Tests for compile_file ---


def test_compile_file_success(monkeypatch, tmp_path):
    # Assemble
    # Setup a temporary directory to simulate the executables directory.
    executables_dir = tmp_path / "executables"
    executables_dir.mkdir()
    file_path = str(tmp_path / "dummy.c")
    file_name = "dummy.c"
    executable_path = str(executables_dir)
    compiler_tool_full_path = "gcc"
    compiler_warning_flags = "-Wall"
    compiler_feature_flags = "-std=c99"
    compiler_timeout = 5

    # Monkeypatch subprocess.run to simulate a successful compile.
    def fake_run(command, stderr, stdout, universal_newlines, timeout, shell):
        class Result:
            stderr = ""
            stdout = "compiled successfully"

        return Result()

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Monkeypatch os.path.exists to return True when checking for the compiled executable.
    def fake_exists(path):
        if "dummy" in path:
            return True
        return False

    monkeypatch.setattr(os.path, "exists", fake_exists)

    # Act
    executable_name = compile_file(
        file_path,
        file_name,
        executable_path,
        compiler_tool_full_path,
        compiler_warning_flags,
        compiler_feature_flags,
        compiler_timeout,
    )

    # Assert
    assert executable_name == "dummy"


def test_compile_file_failure(monkeypatch, tmp_path):
    # Assemble
    executables_dir = tmp_path / "executables"
    executables_dir.mkdir()
    file_path = str(tmp_path / "dummy.c")
    file_name = "dummy.c"
    executable_path = str(executables_dir)
    compiler_tool_full_path = "gcc"
    compiler_warning_flags = "-Wall"
    compiler_feature_flags = "-std=c99"
    compiler_timeout = 5

    def fake_run(command, stderr, stdout, universal_newlines, timeout, shell):
        class Result:
            stderr = "compilation error"
            stdout = ""

        return Result()

    monkeypatch.setattr(subprocess, "run", fake_run)
    monkeypatch.setattr(os.path, "exists", lambda path: False)

    # Act
    executable_name = compile_file(
        file_path,
        file_name,
        executable_path,
        compiler_tool_full_path,
        compiler_warning_flags,
        compiler_feature_flags,
        compiler_timeout,
    )

    # Assert
    assert executable_name == ""


# # --- Tests for write_crashes_csv and log_crash_information ---


def test_write_crashes_csv(tmp_path):
    # Assemble
    csv_path = str(tmp_path / "results.csv")
    message = "crash data"
    encoded = base64.b64encode(message.encode()).decode()
    crash_detail = CrashDetail(
        executable_name="dummy_exe", base64_message=encoded, is_input_from_file=False
    )

    # Act
    write_crashes_csv(crash_detail, 0, csv_path)
    with open(csv_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Assert
    assert "timestamp,crash_detail,return_code,inputFromFile" in content
    assert encoded in content


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
            "logging_config": {},
            "appname": "dummy_app",
            "version": "1.0",
            "executables_full_path": "/dummy/executables",
            "patched_codes_path": "/dummy/patches",
            "compiler_tool_full_path": "gcc",
            "compiler_warning_flags": "-Wall",
            "compiler_feature_flags": "-std=c99",
            "compile_timeout": 5,
            "run_timeout": 10,
            "patch_eval_results_full_path": "/dummy/results",
            "message_broker_host": "localhost",
            "message_broker_port": 1883,
            "autopatch_crash_detail_input_topic": "dummy_topic",
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
    assert config_obj.appname == "dummy_app"


# # --- Test for on_consume_crash_detail ---


def test_on_consume_crash_detail(monkeypatch):
    # Assemble
    calls = []

    class DummyLoop:
        def call_soon_threadsafe(self, callback, arg):
            calls.append((callback, arg))

    patch_evaluation_service.event_loop = DummyLoop()
    cloud_event_str = "dummy event"

    # Act
    on_consume_crash_detail(cloud_event_str)

    # Assert
    assert len(calls) == 1
    callback, arg = calls[0]
    # Ensure that the callback is the put_nowait method of the async queue.
    assert callback == patch_evaluation_service.async_crash_details_queue.put_nowait
    assert arg == cloud_event_str


# # --- Test for prep_executables_for_evaluation ---


def test_prep_executables_for_evaluation(monkeypatch, tmp_path):
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
    executables, results_dict = prep_executables_for_evaluation(
        str(executables_dir),
        str(patched_codes_dir),
        "dummy_compiler",
        "-Wall",
        "-std=c99",
        5,
    )

    # Assert
    assert "file1" in executables
    assert "file2" in executables
    assert results_dict["file1"]["total_crashes"] == 0
    assert results_dict["file1"]["patched_crashes"] == 0


# # --- Test for process_crash_detail ---


@pytest.mark.asyncio
async def test_process_crash_detail(monkeypatch, tmp_path):

    # Assemble
    dummy_config = dummy_PatchEvalConfig()
    dummy_config.executables_full_path = str(tmp_path / "executables")
    dummy_config.run_timeout = 5
    dummy_config.patch_eval_results_full_path = str(tmp_path / "results")
    os.makedirs(dummy_config.executables_full_path, exist_ok=True)
    os.makedirs(dummy_config.patch_eval_results_full_path, exist_ok=True)
    patch_evaluation_service.config = dummy_config
    patch_evaluation_service.executables_to_process = {"dummy_exe"}
    patch_evaluation_service.results = {
        "dummy_exe": {"total_crashes": 0, "patched_crashes": 0}
    }

    message = "dummy crash"
    encoded = base64.b64encode(message.encode()).decode()
    crash_detail = CrashDetail(
        executable_name="dummy_exe", base64_message=encoded, is_input_from_file=False
    )

    async def fake_run_file_async(*args, **kwargs):
        return 0

    monkeypatch.setattr(patch_evaluation_service, "run_file_async", fake_run_file_async)

    async def fake_log_crash_information(*args, **kwargs):
        pass

    monkeypatch.setattr(
        patch_evaluation_service, "log_crash_information", fake_log_crash_information
    )

    # Act
    await process_crash_detail(crash_detail)

    # Assert
    # Expect total_crashes and patched_crashes to update (since return code 0 counts as a patched crash).
    assert patch_evaluation_service.results["dummy_exe"]["total_crashes"] == 1
    assert patch_evaluation_service.results["dummy_exe"]["patched_crashes"] == 1


# # --- Test for crash_detail_consumer ---


@pytest.mark.asyncio
async def test_crash_detail_consumer(monkeypatch):
    # Assemble
    called = False

    async def fake_process_item(item):
        nonlocal called
        called = True

    monkeypatch.setattr(patch_evaluation_service, "process_item", fake_process_item)

    # Enqueue a dummy cloud event.
    dummy_event = json.dumps(
        {
            "data": {
                "executable_name": "dummy_exe",
                "crash_detail_base64": base64.b64encode("crash".encode()).decode(),
                "is_input_from_file": False,
            }
        }
    )
    patch_evaluation_service.async_crash_details_queue.put_nowait(dummy_event)

    # Act
    # Run the consumer briefly.
    consumer_task = asyncio.create_task(
        patch_evaluation_service.crash_detail_consumer()
    )
    await asyncio.sleep(0.1)
    consumer_task.cancel()
    try:
        await consumer_task
    except asyncio.CancelledError:
        pass

    # Assert
    assert called is True


# --- Test for main() ---
#


@pytest.mark.asyncio
async def test_main(monkeypatch, tmp_path):

    # Because main() enters an infinite wait at the end, we monkeypatch asyncio.Future to return a future that is
    # already done so that main() completes.

    # Assemble
    dummy_config_path = str(tmp_path / "config.json")
    dummy_config_content = json.dumps(
        {
            "logging_config": {},
            "appname": "dummy_app",
            "version": "1.0",
            "executables_full_path": str(tmp_path / "executables"),
            "patched_codes_path": str(tmp_path / "patches"),
            "compiler_tool_full_path": "gcc",
            "compiler_warning_flags": "-Wall",
            "compiler_feature_flags": "-std=c99",
            "compile_timeout": 5,
            "run_timeout": 5,
            "patch_eval_results_full_path": str(tmp_path / "results"),
            "message_broker_host": "localhost",
            "message_broker_port": 1883,
            "autopatch_crash_detail_input_topic": "dummy_topic",
        }
    )
    with open(dummy_config_path, "w") as f:
        f.write(dummy_config_content)
    monkeypatch.setenv("PATCH_EVAL_SVC_CONFIG", dummy_config_path)

    # Prepare a dummy config object.
    dummy_config = PatchEvalConfig(**json.loads(dummy_config_content))
    monkeypatch.setattr(
        patch_evaluation_service, "load_config", lambda path, logger: dummy_config
    )
    monkeypatch.setattr(
        patch_evaluation_service,
        "init_logging",
        lambda config, appname: logging.getLogger("dummy"),
    )
    monkeypatch.setattr(
        patch_evaluation_service,
        "prep_executables_for_evaluation",
        lambda *args, **kwargs: (
            {"dummy_exe"},
            {"dummy_exe": {"total_crashes": 0, "patched_crashes": 0}},
        ),
    )

    # Dummy MessageBrokerClient with a no-op consume.
    class DummyMessageBrokerClient:
        def __init__(self, host, port, logger):
            pass

        def consume(self, topic, callback):
            pass

    monkeypatch.setattr(
        patch_evaluation_service, "MessageBrokerClient", DummyMessageBrokerClient
    )

    # Replace asyncio.Future with one that is already completed.
    class DummyFuture(asyncio.Future):
        def __init__(self):
            super().__init__()
            self.set_result(None)

    monkeypatch.setattr(asyncio, "Future", lambda: DummyFuture())

    # Run main; it should complete because the future is already done.
    try:
        await asyncio.wait_for(patch_evaluation_service.main(), timeout=1)
    except asyncio.TimeoutError:
        pytest.fail("main() did not complete as expected")
