import logging
import subprocess
from unittest.mock import MagicMock, patch

import pytest
from autopatchshared import make_compile


@pytest.fixture(autouse=True)
def dummy_logger():
    """Fixture to provide a dummy logger."""
    logger = MagicMock(DummyLogger())
    yield logger
    logger.messages.clear()


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

    def log(self, msg, *args, **kwargs):
        self.messages.append(msg)


@pytest.fixture
def dummy_args():
    return {
        "project_directory_full_path": "/fake/project",
        "output_executable_fully_qualified_path": "/fake/project/output.bin",
        "compiler_tool_full_path": "/usr/bin/gcc",
        "make_tool_full_path": "/usr/bin/make",
    }


def make_popen_mock(
    returncode=0, stdout="build success", stderr="", raise_timeout=False
):
    popen_mock = MagicMock()
    proc = popen_mock.__enter__.return_value

    if raise_timeout:

        def communicate_side_effect(timeout=None):
            raise subprocess.TimeoutExpired(cmd="make", timeout=10)

        proc.communicate.side_effect = communicate_side_effect
    else:
        proc.communicate.return_value = (stdout, stderr)

    proc.returncode = returncode
    return popen_mock


# --- NORMAL CASES ---


def test_make_compile_success(dummy_args, dummy_logger):
    with patch("subprocess.Popen", return_value=make_popen_mock(returncode=0)):
        result = make_compile(**dummy_args, logger=dummy_logger)
        assert result is True
        dummy_logger.error.assert_not_called()


def test_make_compile_failure_nonzero_returncode(dummy_args, dummy_logger):
    with patch(
        "subprocess.Popen",
        return_value=make_popen_mock(returncode=1, stderr="error!", stdout="trace"),
    ):
        result = make_compile(**dummy_args, logger=dummy_logger)
        assert result is False
        dummy_logger.error.assert_any_call("Compilation failed with return code 1")
        dummy_logger.error.assert_any_call("stderr error!")
        dummy_logger.error.assert_any_call("stdout trace")


# --- EDGE CASES ---


def test_make_compile_timeout(dummy_args, dummy_logger):
    with patch("subprocess.Popen", return_value=make_popen_mock(raise_timeout=True)):
        with pytest.raises(subprocess.TimeoutExpired):
            result = make_compile(**dummy_args, logger=dummy_logger)
            assert result is False
            dummy_logger.error.assert_any_call(
                "Compilation failed with Command 'make' timed out after 10 seconds"
            )


def test_make_compile_empty_output(dummy_args, dummy_logger):
    with patch(
        "subprocess.Popen",
        return_value=make_popen_mock(returncode=0, stdout="", stderr=""),
    ):
        result = make_compile(**dummy_args, logger=dummy_logger)
        assert result is True
        dummy_logger.error.assert_not_called()


# --- ROBUSTNESS CASES ---


def test_make_compile_exception_in_popen(dummy_args, dummy_logger):
    with patch("subprocess.Popen", side_effect=OSError("spawn failed")):
        with pytest.raises(OSError):
            result = make_compile(**dummy_args, logger=dummy_logger)
            assert result is False
            dummy_logger.error.assert_any_call("Compilation failed with spawn failed")


def test_make_compile_invalid_paths(dummy_logger):
    args = {
        "project_directory_full_path": "",
        "output_executable_fully_qualified_path": "",
        "compiler_tool_full_path": "",
        "make_tool_full_path": "",
    }
    with patch(
        "subprocess.Popen",
        return_value=make_popen_mock(returncode=1, stderr="bad path"),
    ):
        result = make_compile(**args, logger=dummy_logger)
        assert result is False
        dummy_logger.error.assert_any_call("stderr bad path")
