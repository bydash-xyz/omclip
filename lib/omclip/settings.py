"""Settings: `~/.config/omclip/settings`, `key=value`, validated on load and on set.

A bad value must never crash the daemon: it falls back to the default and is
reported (`config list` shows effective values, the daemon logs one warning line).
`duration` here uses the settings dialect — a bare integer is **seconds** — which is
deliberately not the CLI dialect (`omclip on 10` = 10 minutes). See `duration.py`.
"""

import os
import re

from . import duration, paths

#: Effective defaults. Scope defaults to `both` so mirroring always operates
#: on both peers (Mac and iPhone).
DEFAULTS = {
    "scope": "both",
    "duration": "forever",
    "mac_host": "localhost",
    "mac_port": 49152,
    "phone_address": "",
    "poll_seconds": 2.0,
    "idle_poll_seconds": 20.0,
    "locked_poll_seconds": 30.0,
    "max_bytes": 256 * 1024 * 1024,
    "ble_trigger": True,
    "preview": True,
    "notify": False,
    "log_level": "info",
    "identity_dir": paths.DEFAULT_IDENTITY_DIR,
    "keys_dir": paths.DEFAULT_KEYS_DIR,
    "download_dir": paths.DEFAULT_DOWNLOAD_DIR,
}

SCOPES = ("mac", "phone", "both")
LOG_LEVELS = ("error", "warn", "info", "debug")
BOOLS = ("true", "false", "yes", "no", "1", "0", "on", "off")

_HOST_RE = re.compile(r"^[A-Za-z0-9_.:%-]+$")


def _bool(value):
    text = str(value).strip().lower()
    if text in ("true", "yes", "1", "on"):
        return True
    if text in ("false", "no", "0", "off"):
        return False
    raise ValueError("expected true/false, got %r" % value)


def _float(value, lo, hi):
    try:
        number = float(value)
    except (TypeError, ValueError):
        raise ValueError("expected a number, got %r" % value)
    if not (lo <= number <= hi):
        raise ValueError("out of range %s..%s" % (lo, hi))
    return number


def _int(value, lo, hi):
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        raise ValueError("expected an integer, got %r" % value)
    if not (lo <= number <= hi):
        raise ValueError("out of range %s..%s" % (lo, hi))
    return number


def validate(key, value):
    """Coerce+validate one setting. Returns (ok, coerced_or_None, error_or_None)."""
    try:
        return True, _coerce(key, value), None
    except ValueError as exc:
        return False, None, str(exc)


def _coerce(key, value):
    if key == "scope":
        text = str(value).strip().lower()
        if text not in SCOPES:
            raise ValueError("scope must be one of %s" % ", ".join(SCOPES))
        return text
    if key == "duration":
        return duration.parse_settings_duration(value)[0]
    if key == "mac_host":
        text = str(value).strip()
        if not text or not _HOST_RE.match(text):
            raise ValueError("mac_host must be a hostname or IP literal")
        return text
    if key == "mac_port":
        return _int(value, 1, 65535)
    if key == "phone_address":
        text = str(value).strip()
        if text and not _HOST_RE.match(text):
            raise ValueError("phone_address must be empty or an address literal")
        return text
    if key in ("poll_seconds", "locked_poll_seconds"):
        return _float(value, 0.5, 3600.0)
    if key == "idle_poll_seconds":
        return _float(value, 1.0, 3600.0)
    if key == "max_bytes":
        return _int(value, 1024, 1 << 30)
    if key in ("ble_trigger", "preview", "notify"):
        return _bool(value)
    if key == "log_level":
        text = str(value).strip().lower()
        if text not in LOG_LEVELS:
            raise ValueError("log_level must be one of %s" % ", ".join(LOG_LEVELS))
        return text
    if key in ("identity_dir", "keys_dir", "download_dir"):
        text = os.path.expanduser(str(value).strip())
        if not text:
            raise ValueError("%s must not be empty" % key)
        # `download_dir` is where a file is *written*, so a relative path is a bug: the
        # daemon's cwd is `/` under the unit, and the file would land somewhere nobody
        # looks. The read-only dirs above stay permissive (they are resolved, not written).
        if key == "download_dir" and not os.path.isabs(text):
            raise ValueError("download_dir must be an absolute path (got %r)" % value)
        return text
    raise ValueError("unknown setting %r" % key)


def parse_text(text):
    """Parse a settings file body → (settings, warnings). Never raises."""
    values = dict(DEFAULTS)
    warnings = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            warnings.append("line %d: not key=value (%r)" % (lineno, raw.strip()))
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if key not in DEFAULTS:
            warnings.append("line %d: unknown setting %r ignored" % (lineno, key))
            continue
        ok, coerced, error = validate(key, value)
        if ok:
            values[key] = coerced
        else:
            warnings.append("line %d: %s=%r: %s (using default %r)"
                            % (lineno, key, value, error, DEFAULTS[key]))
    return values, warnings


def load(path=None):
    """Read settings from disk → (settings, warnings). Missing file = defaults."""
    path = path or paths.SETTINGS_FILE
    try:
        with open(path, "r", encoding="utf-8") as fh:
            text = fh.read()
    except FileNotFoundError:
        return dict(DEFAULTS), []
    except OSError as exc:
        return dict(DEFAULTS), ["cannot read %s: %s" % (path, exc)]
    return parse_text(text)


def write(values, path=None):
    """Persist effective values (used by `config set`)."""
    path = path or paths.SETTINGS_FILE
    paths.ensure_dir(os.path.dirname(path))
    lines = ["# omclip settings — see README.md. Values are validated on load."]
    for key in DEFAULTS:
        value = values.get(key, DEFAULTS[key])
        if isinstance(value, bool):
            value = "true" if value else "false"
        lines.append("%s=%s" % (key, value))
    text = "\n".join(lines) + "\n"
    tmp = "%s.tmp.%d" % (path, os.getpid())
    with open(tmp, "w", encoding="utf-8") as fh:
        fh.write(text)
    os.replace(tmp, path)
    return text


def scope_list(value=None):
    """`scope` → the list that appears in `status.scope`. Defaults to both."""
    value = value or DEFAULTS["scope"]
    if value == "both":
        return ["mac", "phone"]
    return [value]


class Settings(dict):
    """A dict with the defaults already folded in."""

    def __init__(self, values=None, warnings=None):
        super().__init__(DEFAULTS)
        if values:
            self.update({k: v for k, v in values.items() if k in DEFAULTS})
        self.warnings = list(warnings or [])

    @classmethod
    def load(cls, path=None):
        values, warnings = load(path)
        return cls(values, warnings)

    def scopes(self):
        return scope_list(self.get("scope"))

    def as_dict(self):
        return {k: self[k] for k in DEFAULTS}
