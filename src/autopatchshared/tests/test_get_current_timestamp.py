import re
from datetime import datetime

from autopatchshared import get_current_timestamp

ISO_8601_UTC_PATTERN = r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$"


def test_normal_timestamp_format():
    """Normal case: Ensure output matches ISO 8601 UTC pattern."""
    ts = get_current_timestamp()
    assert re.match(ISO_8601_UTC_PATTERN, ts), f"Invalid timestamp format: {ts}"


def test_timestamp_is_utc():
    """Robust case: Ensure timestamp ends with 'Z' indicating UTC."""
    ts = get_current_timestamp()
    assert ts.endswith("Z")


def test_timestamp_is_close_to_now():
    """Edge case: Timestamp should be within a few seconds of current UTC time."""
    ts = get_current_timestamp()
    parsed_ts = datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
    now_utc = datetime.utcnow()
    delta = abs((now_utc - parsed_ts).total_seconds())
    assert delta < 5  # allow 5s drift
