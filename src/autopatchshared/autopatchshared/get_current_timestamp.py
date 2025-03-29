from datetime import datetime, timezone


def get_current_timestamp() -> str:
    """
    Get the current timestamp in ISO 8601 format.
    """
    return (
        datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")
    )
