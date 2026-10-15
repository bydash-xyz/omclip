"""Duration/window parsing.

Two dialects, deliberately different because the frozen contract says so:

* CLI `omclip on [DURATION]`: a **bare integer means minutes** (`on 10` = 10 min),
  plus `30s`, `10m`, `1h`, `forever` (the default), `once` (stop after the first
  successful mirror).
* Settings `duration`: a bare integer means **seconds**, or `forever`.

Canonical strings are lowercase and unit-suffixed (`10m`, `30s`, `1h`), which is what
`status.duration` reports.
"""

import re
import time

FOREVER = "forever"
ONCE = "once"

_BARE = re.compile(r"^\d+$")
_UNIT = re.compile(r"^(\d+)([smh])$")
_COMPOUND = re.compile(r"^(?:\d+[smh])+$")
_PART = re.compile(r"(\d+)([smh])")

_SECONDS = {"s": 1, "m": 60, "h": 3600}


def _seconds_of(text):
    total = 0
    for value, unit in _PART.findall(text):
        total += int(value) * _SECONDS[unit]
    return total


def parse_duration(text, *, default_minutes_units="m", allow_once=True, allow_forever=True):
    """Parse a duration string → (canonical, seconds or None, once: bool).

    Raises ValueError on anything else; callers decide the fallback.
    """
    if text is None or text == "":
        return FOREVER, None, False
    text = str(text).strip().lower()
    if text == FOREVER:
        if not allow_forever:
            raise ValueError("forever is not allowed here")
        return FOREVER, None, False
    if text == ONCE:
        if not allow_once:
            raise ValueError("once is not allowed here")
        return ONCE, None, True
    if _BARE.match(text):
        seconds = int(text) * _SECONDS[default_minutes_units]
        return canon(seconds, default_unit=default_minutes_units), seconds, False
    if _UNIT.match(text) or _COMPOUND.match(text):
        seconds = _seconds_of(text)
        if seconds <= 0:
            raise ValueError("duration must be positive")
        return text, seconds, False
    raise ValueError("bad duration %r (use 30s/10m/1h/forever/once)" % text)


def parse_settings_duration(text):
    """Settings dialect: bare integer = seconds, or `forever`. No `once`."""
    if text is None or text == "":
        return FOREVER, None
    text = str(text).strip().lower()
    if text == FOREVER:
        return FOREVER, None
    if _BARE.match(text):
        seconds = int(text)
        if seconds <= 0:
            raise ValueError("duration must be positive")
        # Canonical form only: `config list` should read "10m", not the raw "600".
        return canon(seconds), seconds
    if _UNIT.match(text) or _COMPOUND.match(text):
        seconds = _seconds_of(text)
        if seconds <= 0:
            raise ValueError("duration must be positive")
        return canon(seconds), seconds
    raise ValueError("bad duration %r (seconds or forever)" % text)


def canon(seconds, default_unit="m"):
    """Human-friendly canonical form: exact hours/minutes, else seconds."""
    if seconds is None:
        return FOREVER
    for unit, size in (("h", 3600), ("m", 60)):
        if seconds % size == 0 and seconds >= size:
            return "%d%s" % (seconds // size, unit)
    return "%ds" % seconds


def format_seconds(seconds):
    """Prose for humans: 1h02m, 10m00s, 45s."""
    if seconds is None:
        return "forever"
    seconds = int(seconds)
    if seconds < 0:
        seconds = 0
    if seconds >= 3600:
        return "%dh%02dm" % (seconds // 3600, (seconds % 3600) // 60)
    if seconds >= 60:
        return "%dm%02ds" % (seconds // 60, seconds % 60)
    return "%ds" % seconds


class Window:
    """A started window: `since`, `expires_at`, `seconds_left`, `once`."""

    def __init__(self, canonical, seconds, once=False, started_at=None):
        self.duration = canonical
        self.seconds = seconds
        self.once = once
        self.since = time.time() if started_at is None else started_at

    @property
    def expires_at(self):
        return None if self.seconds is None else self.since + self.seconds

    def seconds_left(self, now=None):
        if self.seconds is None:
            return None
        now = time.time() if now is None else now
        return max(0, int(round(self.expires_at - now)))

    def expired(self, now=None):
        if self.seconds is None:
            return False
        now = time.time() if now is None else now
        return now >= self.expires_at

    def describe(self):
        return self.duration
