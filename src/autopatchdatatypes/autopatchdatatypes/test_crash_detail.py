import base64

import pytest

from autopatchdatatypes import CrashDetail

# Normal Tests (Valid Use Cases)


def test_crash_detail_valid_data():
    message = base64.b64encode(b"Segmentation fault").decode("utf-8")
    crash = CrashDetail(
        executable_name="/usr/bin/app", base64_message=message, is_input_from_file=True
    )

    assert crash.executable_name == "/usr/bin/app"
    assert crash.base64_message == message
    assert crash.is_input_from_file is True


def test_crash_detail_empty_message():
    empty_message = base64.b64encode(b"").decode("utf-8")
    crash = CrashDetail(
        executable_name="/usr/local/bin/empty_input",
        base64_message=empty_message,
        is_input_from_file=False,
    )

    assert crash.base64_message == empty_message


def test_crash_detail_long_message():
    long_message = base64.b64encode(b"A" * 10000).decode("utf-8")
    crash = CrashDetail(
        executable_name="/usr/bin/heavy_load",
        base64_message=long_message,
        is_input_from_file=True,
    )

    assert crash.base64_message == long_message


# Robust Tests (Invalid Inputs)


def test_crash_detail_invalid_base64_message():
    invalid_message = "NotAValidBase64String!!"

    with pytest.raises(
        ValueError, match="The message must be a valid base64-encoded byte string."
    ):
        CrashDetail(
            executable_name="/usr/bin/bad_input",
            base64_message=invalid_message,
            is_input_from_file=False,
        )


def test_crash_detail_non_string_message():
    non_string_message = 12345  # Not a string

    with pytest.raises(TypeError):
        CrashDetail(
            executable_name="/usr/bin/non_string",
            base64_message=non_string_message,  # type: ignore
            is_input_from_file=True,
        )


def test_crash_detail_none_message():
    with pytest.raises(TypeError):
        CrashDetail(
            executable_name="/usr/bin/none_message",
            base64_message=None,  # type: ignore
            is_input_from_file=False,
        )


# Edge Case Tests (Boundary Testing)


def test_crash_detail_minimum_input():
    min_message = base64.b64encode(b"A").decode("utf-8")
    crash = CrashDetail(
        executable_name="/bin/min_input",
        base64_message=min_message,
        is_input_from_file=False,
    )

    assert crash.base64_message == min_message


def test_crash_detail_special_characters_in_executable():
    message = base64.b64encode(b"Special characters test").decode("utf-8")
    crash = CrashDetail(
        executable_name="/usr/bin/we!rd_ch@rs#$",
        base64_message=message,
        is_input_from_file=True,
    )

    assert crash.executable_name == "/usr/bin/we!rd_ch@rs#$"
