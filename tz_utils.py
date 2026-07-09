"""
tz_utils.py — Display-time timezone conversion (stdlib only, no new dependency)

Storage principle: every timestamp is written and kept in UTC everywhere
(database.py, logger.py, evidence/chain-of-custody, STIX export). That is
unchanged by this module. This module only converts a UTC value to the
timezone configured in config.yaml -> display.timezone, for rendering on
the dashboard, reports, and log viewers.

Uses Python's built-in `zoneinfo` (stdlib since 3.9) — no extra package
required.
"""

from __future__ import annotations
from datetime import datetime, timezone, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

try:
    from config_loader import cfg
    _CONFIGURED_TZ_NAME = cfg.get("display.timezone", "Asia/Kolkata")
except Exception:
    _CONFIGURED_TZ_NAME = "Asia/Kolkata"

# Fixed-offset fallbacks for a few common zones, used only if the IANA tz
# database (the 'tzdata' package) isn't installed — this is the normal
# situation on a stock Windows Python install, which ships no tz database
# at all. These offsets ignore DST, which is an acceptable trade-off for
# a fallback path; installing 'tzdata' (see requirements.txt) restores
# fully correct, DST-aware conversion everywhere.
_FIXED_OFFSET_FALLBACKS = {
    "Asia/Kolkata":       5.5,
    "Asia/Calcutta":      5.5,
    "UTC":                0,
    "Etc/UTC":            0,
    "America/New_York":  -5,
    "America/Chicago":   -6,
    "America/Denver":    -7,
    "America/Los_Angeles":-8,
    "Europe/London":      0,
    "Europe/Paris":       1,
    "Europe/Berlin":      1,
    "Asia/Tokyo":         9,
    "Asia/Shanghai":      8,
    "Asia/Singapore":     8,
    "Australia/Sydney":  10,
}


def _resolve_display_tz(name: str):
    """
    Best-effort resolution of the configured display timezone.
    Never raises — always returns something usable:
      1. Proper ZoneInfo (DST-aware) if the tz database is available.
      2. A fixed-offset timezone for a handful of common zones if not
         (e.g. missing 'tzdata' package on Windows).
      3. Plain UTC as the last resort.
    """
    try:
        return ZoneInfo(name), name, True
    except (ZoneInfoNotFoundError, KeyError, OSError, ModuleNotFoundError):
        pass
    except Exception:
        pass

    if name in _FIXED_OFFSET_FALLBACKS:
        hours = _FIXED_OFFSET_FALLBACKS[name]
        return timezone(timedelta(hours=hours)), f"{name} (fixed offset, no DST)", False

    return timezone.utc, "UTC (tzdata unavailable, no fallback offset known)", False


DISPLAY_TZ, _RESOLVED_TZ_DESC, _TZDATA_OK = _resolve_display_tz(_CONFIGURED_TZ_NAME)

if not _TZDATA_OK:
    import warnings
    warnings.warn(
        f"tz_utils: could not load IANA timezone '{_CONFIGURED_TZ_NAME}' "
        f"(is the 'tzdata' package installed? see requirements.txt). "
        f"Falling back to {_RESOLVED_TZ_DESC}. Dashboard will still work; "
        f"times may be off during DST transitions until 'tzdata' is installed.",
        RuntimeWarning,
        stacklevel=2,
    )


def display_tz_name() -> str:
    """Configured IANA timezone name, e.g. 'Asia/Kolkata'."""
    return _CONFIGURED_TZ_NAME


def display_tz_abbr() -> str:
    """Short label for headers, e.g. 'IST', 'UTC'."""
    try:
        return datetime.now(DISPLAY_TZ).tzname() or _CONFIGURED_TZ_NAME
    except Exception:
        return _CONFIGURED_TZ_NAME


def _as_utc(dt: datetime) -> datetime:
    """Treat naive datetimes (as stored by SQLAlchemy/datetime.utcnow()) as UTC."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def to_local(value) -> datetime | None:
    """
    Convert a naive/aware UTC datetime OR an ISO-8601 string to an
    aware datetime in the configured display timezone.
    Returns None if the input can't be parsed.
    """
    if value is None or value == "":
        return None
    if isinstance(value, str):
        try:
            value = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    if not isinstance(value, datetime):
        return None
    return _as_utc(value).astimezone(DISPLAY_TZ)


def format_local(value, fmt: str = "%Y-%m-%d %H:%M:%S") -> str:
    """Convenience formatter — returns '' if the value can't be parsed."""
    local = to_local(value)
    return local.strftime(fmt) if local else ""


def local_isoformat(value) -> str:
    """ISO-8601 string with the configured local UTC offset, e.g. '...+05:30'."""
    local = to_local(value)
    return local.isoformat() if local else ""
