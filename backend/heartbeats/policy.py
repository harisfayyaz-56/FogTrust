"""The admin-set values the heartbeat endpoint needs (Member 3's PolicyConfig, with safe fallbacks)."""

from django.apps import apps
from django.conf import settings

DEFAULT_WINDOW_S = 30
DEFAULT_INTERVAL_S = 10


def _int_in_range(value, low, high, default):
    return value if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high else default


def current_policy() -> tuple[int, int, int | None]:
    """(timestamp_window_s, heartbeat_interval_s, policy_version). Version is None without the trust app."""
    window = getattr(settings, "HEARTBEAT_TIMESTAMP_WINDOW_S", DEFAULT_WINDOW_S)
    interval = getattr(settings, "HEARTBEAT_INTERVAL_S", DEFAULT_INTERVAL_S)
    version = None
    if apps.is_installed("trust"):
        from trust.models import PolicyConfig

        policy = PolicyConfig.current()
        window = _int_in_range(policy.values.get("timestamp_window_s"), 1, 3600, window)
        interval = _int_in_range(policy.values.get("heartbeat_interval_s"), 1, 3600, interval)
        version = policy.version
    return window, interval, version