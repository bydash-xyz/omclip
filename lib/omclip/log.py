"""Logging to `~/.local/state/omclip/omclip.log`, rotated at 512 KB (1 generation).

Hand-rolled rather than `logging.handlers.RotatingFileHandler` because the daemon
needs exactly one small file, one generation, and a format that reads well in
`omclip log` / `journalctl`.

**Clipboard contents never reach this file.** Only digests, sizes and UTIs are
logged; `clipboard.last_preview` lives in `status.json` only (see `pasteboard.py`).
"""

import os
import time

LEVELS = {"error": 0, "warn": 1, "info": 2, "debug": 3}
MAX_BYTES = 512 * 1024


class Logger:
    def __init__(self, path=None, level="info", max_bytes=MAX_BYTES, echo=False):
        self.path = path
        self.level = level if level in LEVELS else "info"
        self.max_bytes = max_bytes
        self.echo = echo
        self.fh = None
        self.warnings = []
        if path:
            try:
                os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
                self._open()
            except OSError as exc:                       # noqa: BLE001 - never fatal
                self.path = None
                self.warnings.append("cannot open log %s: %s" % (path, exc))

    def _open(self):
        # 'a' + a size check on every write: rotation happens between lines, never
        # mid-line, so a reader (including `omclip log -f`) never sees a torn record.
        self.fh = open(self.path, "a", encoding="utf-8", buffering=1)

    def close(self):
        if self.fh is not None:
            try:
                self.fh.close()
            except OSError:
                pass
            self.fh = None

    def rotate_if_needed(self):
        if not self.path:
            return False
        try:
            if os.path.getsize(self.path) < self.max_bytes:
                return False
        except OSError:
            return False
        self.close()
        try:
            os.replace(self.path, self.path + ".1")
        except OSError:
            pass
        self._open()
        return True

    def enabled(self, level):
        return LEVELS.get(level, 2) <= LEVELS.get(self.level, 2)

    def log(self, level, message, **fields):
        if not self.enabled(level):
            return False
        parts = [time.strftime("%Y-%m-%d %H:%M:%S"), level.upper().ljust(5), message]
        for key, value in fields.items():
            if value is None:
                continue
            parts.append("%s=%s" % (key, value))
        line = " ".join(parts)
        if self.fh is not None:
            self.rotate_if_needed()
            try:
                self.fh.write(line + "\n")
            except OSError:
                pass
        if self.echo:
            print(line, flush=True)
        return True

    def error(self, message, **fields):
        return self.log("error", message, **fields)

    def warn(self, message, **fields):
        return self.log("warn", message, **fields)

    def info(self, message, **fields):
        return self.log("info", message, **fields)

    def debug(self, message, **fields):
        return self.log("debug", message, **fields)


def tail(path, count=20):
    """Last `count` lines of the log (most recent last). Never raises."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except FileNotFoundError:
        return []
    except OSError:
        return []
    return lines[-count:] if count else lines
