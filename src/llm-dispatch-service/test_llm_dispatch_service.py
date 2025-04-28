import base64
import logging
import re
from datetime import datetime as real_datetime
from datetime import timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Final
from unittest.mock import MagicMock

import pytest
from autopatchdatatypes import CpgScanResult, PatchResponse, TransformerMetadata
from llm_dispatch_svc import (
    create_patch_response,
    format_cpg_scan_context,
    full_prompt,
    init_llm_client,
    load_config,
    read_file,
    unwrap_raw_llm_response,
)
from llm_dispatch_svc_config import LLMDispatchSvcConfig

llm_dispatch_svc_module_name_str: Final[str] = "llm_dispatch_svc"


def mock_LLMDispatchSvcConfig() -> LLMDispatchSvcConfig:
    mock_config = {
        "appName": "autopatch.llm-dispatch",
        "appVersion": "0.8.0-beta",
        "appDescription": "A system for managing and dispatching requests to various language models.",
        "system_prompt_full_path": "/workspace/AutoPatch-LLM/src/llm-dispatch/data/prompts/system_prompt.txt",
        "user_prompt_full_path": "/workspace/AutoPatch-LLM/src/llm-dispatch/data/prompts/user_prompt.txt",
        "logging_config": "/workspace/AutoPatch-LLM/src/llm-dispatch/config/dev-logging-config.json",
        "default_model": "gpt-3.5-turbo",
        "default_api_provider": "openai",
        "default_in_memory_provider": "openai",
        "default_max_tokens": 4096,
        "default_temperature": 0.7,
        "default_top_p": 1,
        "default_frequency_penalty": 0,
        "default_presence_penalty": 0,
        "message_broker_client_id": "autopatch-llm-dispatch-client",
        "message_broker_host": "mqtt",
        "message_broker_port": 1883,
        "cpg_scan_result_input_topic": "autopatch/cpg-scan-result",
        "message_broker_topics": {
            "request": "llm/dispatch/request",
            "response": "llm/dispatch/response",
            "error": "llm/dispatch/error",
        },
        "model_router_base_url": "https://openrouter.ai/api/v1",
        "model_router_fallback_model": "google/gemini-2.5-pro-exp-03-25:free",
        "model_router_max_concurrent_requests": 5,
        "model_router_retry_attempts": 3,
        "model_router_timeout_ms": 3000,
        "model_router_retry_delay_ms": 50,
        "models": [
            {
                "gpt-3.5-turbo": {
                    "id": "gpt-3.5-turbo",
                    "name": "GPT-3.5 Turbo",
                    "description": "A powerful language model by OpenAI, suitable for a wide range of tasks.",
                    "model": "gpt-3.5-turbo",
                    "max_tokens": 4096,
                    "temperature": 0.7,
                    "top_p": 1,
                    "frequency_penalty": 0,
                    "presence_penalty": 0,
                    "stop": None,
                    "api_key": "your_openai_api_key",
                    "api_base": "https://api.openai.com/v1",
                    "api_type": "openai",
                    "is_in_memory": False,
                    "in_memory_model_path": "/path/to/gpt-3.5-turbo/model",
                }
            }
        ],
    }

    return LLMDispatchSvcConfig(**mock_config)


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
def mock_logger(monkeypatch):
    logger = MockLogger()
    monkeypatch.setattr("llm_dispatch_svc.logger", logger)
    return logger


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


# -------------------------------------
# Tests for format_cpg_scan_context
# -------------------------------------


def test_format_cpg_scan_context_normal_case():
    """
    Tests the function with a typical, valid CpgScanResult object.
    """
    scan_result = CpgScanResult(
        executable_name="my_program.c",
        vulnerability_severity=7.5,
        vulnerable_line_number=123,
        vulnerable_function="process_input",
        vulnerability_description="Potential buffer overflow via strcpy",
    )
    expected_output = (
        "Vulnerability Context:\n"
        "- Executable Name: my_program.c\n"
        "- Severity Score: 7.5\n"
        "- Vulnerable Line: 123\n"
        "- Vulnerable Function: process_input\n"
        "- Description: Potential buffer overflow via strcpy\n"
    )
    assert format_cpg_scan_context(scan_result) == expected_output


def test_format_cpg_scan_context_robust_empty_strings_zero_severity():
    """
    Tests the function with empty strings for text fields and zero/low severity.
    """
    scan_result = CpgScanResult(
        executable_name="",
        vulnerability_severity=0.0,
        vulnerable_line_number=0,  # Line number 0 is possible in some contexts or just an edge/robust case
        vulnerable_function="",
        vulnerability_description="",
    )
    expected_output = (
        "Vulnerability Context:\n"
        "- Executable Name: \n"
        "- Severity Score: 0.0\n"
        "- Vulnerable Line: 0\n"
        "- Vulnerable Function: \n"
        "- Description: \n"
    )
    assert format_cpg_scan_context(scan_result) == expected_output


def test_format_cpg_scan_context_robust_special_chars_severity():
    """
    Tests the function with special characters in strings and a different severity.
    """
    scan_result = CpgScanResult(
        executable_name="/path/to/program with spaces.elf",
        vulnerability_severity=9.9,
        vulnerable_line_number=42,
        vulnerable_function="main (argc, argv[])",
        vulnerability_description="XSS vulnerability <script>alert('XSS')</script>",
    )
    expected_output = (
        "Vulnerability Context:\n"
        "- Executable Name: /path/to/program with spaces.elf\n"
        "- Severity Score: 9.9\n"
        "- Vulnerable Line: 42\n"
        "- Vulnerable Function: main (argc, argv[])\n"
        "- Description: XSS vulnerability <script>alert('XSS')</script>\n"
    )
    assert format_cpg_scan_context(scan_result) == expected_output


def test_format_cpg_scan_context_edge_case_none_input():
    """
    Tests the function with None as the input context, which is an explicitly handled edge case.
    """
    scan_result = None
    expected_output = ""
    assert format_cpg_scan_context(scan_result) == expected_output


# -------------------------------------
# Tests for load_config
# -------------------------------------


def test_load_config_success(monkeypatch):

    # Assemble
    dummy_path = "/path/to/config.json"
    dummy_config_dict = {"foo": "bar"}

    # Mock load_config_as_json
    def mock_load_config_as_json(path, logger):
        assert path == dummy_path
        return dummy_config_dict

    # Mock LLMDispatchConfig
    class MockLLMDispatchConfig:
        def __init__(self, **kwargs):
            self.config = kwargs

    monkeypatch.setattr(
        "llm_dispatch_svc.load_config_as_json", mock_load_config_as_json
    )
    monkeypatch.setattr("llm_dispatch_svc.LLMDispatchSvcConfig", MockLLMDispatchConfig)

    # Act
    result = load_config(dummy_path)

    # Assert
    assert isinstance(result, MockLLMDispatchConfig)
    assert result.config == dummy_config_dict


def test_load_config_exception(monkeypatch):
    # Assemble
    def mock_load_config_as_json(path, logger):
        raise Exception("mock failure")

    monkeypatch.setattr(
        "llm_dispatch_svc.load_config_as_json", mock_load_config_as_json
    )

    # Assert
    with pytest.raises(Exception, match="mock failure"):
        # Act
        load_config("invalid/path.json")


# -------------------------------------
# Tests for unwrap_raw_llm_response
# -------------------------------------


def test_basic_code_fence():
    input_str = "```python\nprint('Hello, world!')\n```"
    expected = "print('Hello, world!')"
    assert unwrap_raw_llm_response(input_str) == expected


def test_code_fence_no_language():
    input_str = "```\nprint('No language')\n```"
    expected = "print('No language')"
    assert unwrap_raw_llm_response(input_str) == expected


def test_no_code_fence():
    input_str = "This is plain text without any code fence."
    expected = "This is plain text without any code fence."
    assert unwrap_raw_llm_response(input_str) == expected


def test_code_with_extra_whitespace():
    input_str = "```python\n\n    def foo():\n        return 42\n\n```"
    expected = "def foo():\n        return 42"
    assert unwrap_raw_llm_response(input_str) == expected


def test_multiple_code_blocks_returns_first():
    input_str = (
        "```python\nprint('First')\n```\nSome text\n```python\nprint('Second')\n```"
    )
    expected = "print('First')"
    assert unwrap_raw_llm_response(input_str) == expected


def test_empty_string():
    assert unwrap_raw_llm_response("") == ""


def test_code_fence_with_only_whitespace():
    input_str = "```\n   \n  \n```"
    expected = ""
    assert unwrap_raw_llm_response(input_str) == expected


def test_code_fence_with_inner_backticks():
    input_str = "```python\nprint('\\`\\`\\`nested\\`\\`\\`')\n```"
    expected = "print('\\`\\`\\`nested\\`\\`\\`')"
    assert unwrap_raw_llm_response(input_str) == expected


def test_monkeypatched_re(monkeypatch):
    # Monkeypatch re.compile to simulate unexpected behavior
    def mock_compile(pattern):
        class MockPattern:
            def search(self, text):
                return None

        return MockPattern()

    monkeypatch.setattr(re, "compile", mock_compile)
    assert unwrap_raw_llm_response("```python\nx = 1\n```") == "```python\nx = 1\n```"


# -------------------------------------
# Tests for read_file
# -------------------------------------


@pytest.mark.asyncio
async def test_read_file_normal_case(tmp_path):
    # Assemble
    test_file = tmp_path / "test.txt"
    test_content = "Hello, world!"
    test_file.write_text(test_content)

    # Act
    result = await read_file(str(test_file))

    # Assert
    assert result == test_content


@pytest.mark.asyncio
async def test_read_file_empty_path(caplog):
    """Be sure app doesn't crash when empty path is passed"""
    # Assemble
    empty_path: Final[str] = ""

    # Act
    res = await read_file(empty_path)

    # Assert
    assert res == ""


@pytest.mark.asyncio
async def test_read_file_file_not_found(tmp_path):
    # Assemble
    non_existent = tmp_path / "missing.txt"

    # Act
    result = await read_file(str(non_existent))
    # Assert
    assert result == ""


@pytest.mark.asyncio
async def test_read_file_large_file(tmp_path):
    # Assemble
    test_file = tmp_path / "large.txt"
    test_content = "A" * 10**6  # 1 MB of data
    test_file.write_text(test_content)

    # Act
    result = await read_file(str(test_file))

    # Assert
    assert result == test_content


@pytest.mark.asyncio
async def test_read_file_utf8_binary_content(tmp_path):
    # Assemble
    test_file = tmp_path / "binary.txt"
    binary_data = b"\xff\xfe\xfa"  # Invalid UTF-8 bytes
    test_file.write_bytes(binary_data)

    # Act
    result = await read_file(str(test_file))

    # Assert
    assert result == ""


@pytest.mark.asyncio
async def test_read_file_invalid_utf8_binary_content(tmp_path):
    # Assemble
    test_file = tmp_path / "binary.txt"
    binary_data = b"\x00\x01\x02\x03"  # Valid UTF-8 bytes
    test_file.write_bytes(binary_data)

    # Act
    await read_file(str(test_file))


# -------------------------------------
# Tests for full_prompt
# -------------------------------------

HELLO_WORLD_C: Final[
    str
] = """#include <stdio.h>

int main() {
    printf("Hello, world!\\n");
    return 0;
}
"""


@pytest.mark.asyncio
async def test_full_prompt_normal(monkeypatch, mock_logger):
    async def mock_read_file(path):
        return HELLO_WORLD_C

    monkeypatch.setattr("llm_dispatch_svc.read_file", mock_read_file)

    cpgscanresult = CpgScanResult(
        executable_name="program.c",
        vulnerability_severity=7.5,
        vulnerable_line_number=123,
        vulnerable_function="process_input",
        vulnerability_description="Potential buffer overflow via strcpy",
    )
    expected: Final[
        str
    ] = """#include <stdio.h>

int main() {
    printf("Hello, world!\\n");
    return 0;
}

#include <stdio.h>

int main() {
    printf("Hello, world!\\n");
    return 0;
}

Vulnerability Context:
- Executable Name: program.c
- Severity Score: 7.5
- Vulnerable Line: 123
- Vulnerable Function: process_input
- Description: Potential buffer overflow via strcpy

Here is the source code (starting at line 1):
---

#include <stdio.h>

int main() {
    printf("Hello, world!\\n");
    return 0;
}
"""

    # Act
    result = await full_prompt("system.txt", "user.txt", "program.c", cpgscanresult)
    assert result == expected

    assert any(
        "Created Full Prompt for: program.c" in msg for msg in mock_logger.messages
    )
    assert any("Full prompt:" in msg for msg in mock_logger.messages)


@pytest.mark.asyncio
async def test_full_prompt_empty_files(monkeypatch):
    async def mock_read_file(path):
        return ""

    monkeypatch.setattr("llm_dispatch_svc.read_file", mock_read_file)

    result = await full_prompt("empty_system.txt", "empty_user.txt", "empty_program.c")
    assert result == "Here is the source code (starting at line 1):\n---\n"


@pytest.mark.asyncio
async def test_full_prompt_large_file(monkeypatch):
    large_data = HELLO_WORLD_C * 1000

    async def mock_read_file(path):
        return large_data

    monkeypatch.setattr("llm_dispatch_svc.read_file", mock_read_file)

    result = await full_prompt("large_system.txt", "large_user.txt", "large_program.c")
    expected = f"{large_data}\n{large_data}\n---\n{large_data}"
    assert result == expected


@pytest.mark.asyncio
async def test_full_prompt_missing_file(monkeypatch):
    async def mock_read_file(path):
        raise FileNotFoundError(f"{path} not found")

    monkeypatch.setattr("llm_dispatch_svc.read_file", mock_read_file)

    with pytest.raises(FileNotFoundError):
        await full_prompt("missing_system.txt", "missing_user.txt", "missing_program.c")


@pytest.mark.asyncio
async def test_full_prompt_mixed_content(monkeypatch):
    async def mock_read_file(path):
        filename = Path(path).name
        if filename == "program.c":
            return HELLO_WORLD_C
        return f"// {filename} instructions"

    monkeypatch.setattr("llm_dispatch_svc.read_file", mock_read_file)

    result = await full_prompt("system.txt", "user.txt", "program.c")
    expected = (
        "// system.txt instructions\n// user.txt instructions\n---\n" + HELLO_WORLD_C
    )
    assert result == expected


# -------------------------------------
# Tests for init_llm_client
# -------------------------------------


@pytest.mark.asyncio
async def test_init_llm_client_normal(monkeypatch):
    # Assemble
    mock_client = SimpleNamespace(register_strategy=MagicMock())
    mock_api_strategy = SimpleNamespace(register=MagicMock())
    mock_in_memory_strategy = SimpleNamespace(register=MagicMock())
    mock_api_llm = object()
    mock_in_memory_llm = object()

    monkeypatch.setattr("llm_dispatch_svc.LLMClient", lambda: mock_client)
    monkeypatch.setattr("llm_dispatch_svc.ApiLLMStrategy", lambda: mock_api_strategy)
    monkeypatch.setattr(
        "llm_dispatch_svc.InMemoryLLMStrategy", lambda: mock_in_memory_strategy
    )

    def fake_api_llm(name, api_key, endpoint):
        assert name in ["gpt-4", "gpt-3.5"]
        return mock_api_llm

    def fake_in_memory_llm(name, model):
        assert name == "LocalModel"
        assert model == "dummy_model"
        return mock_in_memory_llm

    monkeypatch.setattr("llm_dispatch_svc.ApiLLM", fake_api_llm)
    monkeypatch.setattr("llm_dispatch_svc.InMemoryLLM", fake_in_memory_llm)

    models = ["gpt-4", "gpt-3.5"]
    # Act
    client = await init_llm_client(models, "dummy-key", "http://localhost")

    # Assert
    assert client is mock_client
    assert mock_api_strategy.register.call_count == len(models)
    mock_in_memory_strategy.register.assert_called_once_with(mock_in_memory_llm)
    mock_client.register_strategy.assert_any_call("api", mock_api_strategy)
    mock_client.register_strategy.assert_any_call("in_memory", mock_in_memory_strategy)


@pytest.mark.asyncio
async def test_init_llm_client_empty_models(monkeypatch):
    # Assemble
    mock_client = SimpleNamespace(register_strategy=MagicMock())
    mock_api_strategy = SimpleNamespace(register=MagicMock())
    mock_in_memory_strategy = SimpleNamespace(register=MagicMock())
    mock_in_memory_llm = object()

    monkeypatch.setattr("llm_dispatch_svc.LLMClient", lambda: mock_client)
    monkeypatch.setattr("llm_dispatch_svc.ApiLLMStrategy", lambda: mock_api_strategy)
    monkeypatch.setattr(
        "llm_dispatch_svc.InMemoryLLMStrategy", lambda: mock_in_memory_strategy
    )
    monkeypatch.setattr(
        "llm_dispatch_svc.InMemoryLLM", lambda name, model: mock_in_memory_llm
    )

    models = []

    # Act
    client = await init_llm_client(models, "dummy", "http://localhost")

    # Assert
    assert client is mock_client
    mock_api_strategy.register.assert_not_called()
    mock_in_memory_strategy.register.assert_called_once_with(mock_in_memory_llm)
    mock_client.register_strategy.assert_any_call("api", mock_api_strategy)


@pytest.mark.asyncio
async def test_init_llm_client_api_llm_failure(monkeypatch):
    # Assemble
    mock_client = SimpleNamespace(register_strategy=MagicMock())
    mock_api_strategy = SimpleNamespace(register=MagicMock())
    mock_in_memory_strategy = SimpleNamespace(register=MagicMock())

    monkeypatch.setattr("llm_dispatch_svc.LLMClient", lambda: mock_client)
    monkeypatch.setattr("llm_dispatch_svc.ApiLLMStrategy", lambda: mock_api_strategy)
    monkeypatch.setattr(
        "llm_dispatch_svc.InMemoryLLMStrategy", lambda: mock_in_memory_strategy
    )

    def fail_api_llm(name, api_key, endpoint):
        raise ValueError("bad model")

    monkeypatch.setattr("llm_dispatch_svc.ApiLLM", fail_api_llm)

    # Assert
    with pytest.raises(ValueError, match="bad model"):
        # Act
        await init_llm_client(["invalid"], "badkey", "url")


# -------------------------------------
# Tests for create_patch_response
# -------------------------------------


@pytest.mark.asyncio
async def test_create_patch_response_with_colon(monkeypatch):
    def mock_unwrap_raw_llm_response(response):
        return "patched_code_here"

    monkeypatch.setattr(
        "llm_dispatch_svc.unwrap_raw_llm_response", mock_unwrap_raw_llm_response
    )

    raw_response = {
        "response": "some_raw_patch",
        "llm_name": "meta-llama/llama-4-maverick:free",
    }
    program_uid = "test_program.c"

    result = await create_patch_response(raw_response, program_uid)

    expected_patch_snippet = base64.b64encode(b"patched_code_here").decode("utf-8")
    assert isinstance(result, PatchResponse)
    assert result.executable_name == "test_program"
    assert result.patch_snippet_base64 == expected_patch_snippet
    assert result.status == "success"
    assert result.TransformerMetadata == TransformerMetadata(
        llm_name="llama-4-maverick",
        llm_flavor="meta-llama",
        llm_version="not available",
    )


@pytest.mark.asyncio
async def test_create_patch_response_without_colon(monkeypatch):
    def mock_unwrap_raw_llm_response(response):
        return "another_patch_content"

    monkeypatch.setattr(
        "llm_dispatch_svc.unwrap_raw_llm_response", mock_unwrap_raw_llm_response
    )

    raw_response = {
        "response": "raw_patch_data",
        "llm_name": "google/gemini-2.5-pro-preview-03-25",
    }
    program_uid = "program_under_test.c"

    result = await create_patch_response(raw_response, program_uid)

    expected_patch_snippet = base64.b64encode(b"another_patch_content").decode("utf-8")
    assert isinstance(result, PatchResponse)
    assert result.executable_name == "program_under_test"
    assert result.patch_snippet_base64 == expected_patch_snippet
    assert result.status == "success"
    assert result.TransformerMetadata == TransformerMetadata(
        llm_name="gemini-2.5-pro-preview-03-25",
        llm_flavor="google",
        llm_version="not available",
    )


@pytest.mark.asyncio
async def test_create_patch_response_no_patch(monkeypatch):

    def mock_unwrap_raw_llm_response(response):
        return "No response"

    monkeypatch.setattr(
        "llm_dispatch_svc.unwrap_raw_llm_response", mock_unwrap_raw_llm_response
    )

    raw_response = {
        "response": "no_patch",
        "llm_name": "some-provider/some-model",
    }
    program_uid = "nopatch_program.c"

    result = await create_patch_response(raw_response, program_uid)

    expected_patch_snippet = base64.b64encode(b"No response").decode("utf-8")
    assert isinstance(result, PatchResponse)
    assert result.executable_name == "nopatch_program"
    assert result.patch_snippet_base64 == expected_patch_snippet
    assert result.status == "fail"
    assert result.TransformerMetadata == TransformerMetadata(
        llm_name="some-model",
        llm_flavor="some-provider",
        llm_version="not available",
    )


@pytest.mark.asyncio
async def test_create_patch_response_program_name_no_suffix(monkeypatch):
    def mock_unwrap_raw_llm_response(response):
        return "patched_data"

    monkeypatch.setattr(
        "llm_dispatch_svc.unwrap_raw_llm_response", mock_unwrap_raw_llm_response
    )

    raw_response = {
        "response": "some_response",
        "llm_name": "org/example-model:paid",
    }
    program_uid = "already_clean_name"

    result = await create_patch_response(raw_response, program_uid)

    assert result.executable_name == "already_clean_name"  # No .c suffix to remove
