"""Small JSON files with atomic replacement, plus the desired/runtime records.

`status.json` is written at ≥ 1 Hz by the daemon, so it must never be observed
half-written: `write_json` writes a sibling temp file and `os.replace`s it (atomic
on the same filesystem, which is guaranteed because the temp file shares the dir).
"""

import json
import os
import tempfile
import time

from . import paths

#: What `omclip on` records before starting the unit. The daemon reads it at
#: startup, so the unit can be started by anything (panel, systemd, user).
DESIRED_DEFAULTS = {"scope": ["mac", "phone"], "duration": "forever", "once": False,
                    "requested_at": None}

#: What the running daemon records about itself (ownership + window).
RUNTIME_DEFAULTS = {"pid": None, "started_at": None, "since": None, "expires_at": None,
                    "duration": None, "scope": [], "bluetooth_owned": False,
                    "omdrop_owned": False, "omdrop_window": None}


def write_json(path, obj):
    """Atomically write `obj` as JSON to `path` (tmp file + os.replace)."""
    paths.ensure_dir(os.path.dirname(path))
    fd, tmp = tempfile.mkstemp(prefix=".%s." % os.path.basename(path), dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, separators=(",", ":"), sort_keys=False)
            fh.write("\n")
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return path


def read_json(path, default=None):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (FileNotFoundError, ValueError, OSError):
        return default


def remove(path):
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    except OSError:
        pass


def load_desired(path=None):
    doc = read_json(path or paths.DESIRED_FILE, None)
    if not isinstance(doc, dict):
        return None
    merged = dict(DESIRED_DEFAULTS)
    merged.update(doc)
    return merged


def save_desired(doc, path=None):
    return write_json(path or paths.DESIRED_FILE, doc)


def clear_desired(path=None):
    remove(path or paths.DESIRED_FILE)


def load_runtime(path=None):
    doc = read_json(path or paths.RUNTIME_FILE, None)
    if not isinstance(doc, dict):
        return dict(RUNTIME_DEFAULTS)
    merged = dict(RUNTIME_DEFAULTS)
    merged.update(doc)
    return merged


def save_runtime(doc, path=None):
    return write_json(path or paths.RUNTIME_FILE, doc)


def clear_runtime(path=None):
    remove(path or paths.RUNTIME_FILE)


def load_phone(path=None):
    """The phone memory that outlives a daemon run (runtime.json is cleared on stop)."""
    doc = read_json(path or paths.PHONE_FILE, None)
    return doc if isinstance(doc, dict) else {}


def save_phone(doc, path=None):
    return write_json(path or paths.PHONE_FILE, doc)


BULK_KEEP = 10


def save_bulk_evidence(peer_key, doc, directory=None, now=None):
    """Write one bulk-mode evidence file and keep only the newest BULK_KEEP."""
    directory = directory or paths.BULK_DIR
    stamp = time.strftime("%Y%m%dT%H%M%S", time.localtime(now))
    path = write_json(os.path.join(directory, "%s-%s.json" % (stamp, peer_key)), doc)
    names = sorted(n for n in os.listdir(directory) if n.endswith(".json"))
    for name in names[:-BULK_KEEP]:
        remove(os.path.join(directory, name))
    return path
