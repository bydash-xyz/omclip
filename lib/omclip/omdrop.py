"""`omdrop` integration — the AWDL radio window, with ownership.

The iPhone peer only exists while `awdl0` is up, and `awdl0` only exists inside an
`omdrop` window. omclip therefore *borrows* omdrop:

* Scope `phone`/`both` and omdrop is off → `omclip on` starts `omdrop on <duration>`
  and records `omdrop_owned: true` in the runtime record.
* `omclip off` (and daemon shutdown) closes **only** windows it opened; a window the
  user or `omdrop` itself owns is left alone.
* Window state is read from `omdrop status --json` — never from its human output.

omclip coordinates with Bluetooth: starting an AWDL window ensures `bluetooth.service`
is active so nearby iPhones can receive BLE wake advertisements.
"""

import json
import os
import shutil
import subprocess

from . import paths

TOOL_TIMEOUT = 8.0


def tool_path():
    """Absolute path of the `omdrop` binary (systemd user services have a thin PATH)."""
    for candidate in (os.path.join(paths.BIN_DIR, "omdrop"), "/usr/local/bin/omdrop",
                      "/usr/bin/omdrop"):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which("omdrop")


def parse_status(text):
    """`omdrop status --json` → dict (None when it is not a JSON object)."""
    try:
        doc = json.loads(text)
    except (ValueError, TypeError):
        return None
    return doc if isinstance(doc, dict) else None


def _run(args, timeout=TOOL_TIMEOUT):
    binary = tool_path()
    if binary is None:
        return 127, "", "omdrop not found"
    try:
        proc = subprocess.run([binary] + args, capture_output=True, timeout=timeout,
                              check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace"),
            proc.stderr.decode("utf-8", "replace"))


def status():
    """Live `omdrop status --json` (None when omdrop is missing or unhappy)."""
    rc, out, _err = _run(["status", "--json"], timeout=4.0)
    if rc != 0:
        return None
    return parse_status(out)


#: `reason` values the radio half reports while its session is live (`unproven`: up, but no
#: receive seen yet); anything else (`expired`, `stopped`, `no_awdl0`) is what its teardown
#: leaves behind.
_RADIO_LIVE_REASONS = (None, "ok", "unproven")


def radio_collapsed(doc):
    """True when the receiver still runs but the radio half has torn itself down.

    Measured 2026-10-13: omdrop's root supervisor counts its deadline on the wall clock
    while the user-level window timer is monotonic, so after a suspend longer than the
    window the supervisor tears AWDL + Bluetooth down on resume while `status` still says
    `receiving: true` with minutes `remaining` — `visible: false, reason: "expired"`.
    """
    if not isinstance(doc, dict) or not doc.get("receiving"):
        return False
    return doc.get("visible") is False and doc.get("reason") not in _RADIO_LIVE_REASONS


def window_active(doc):
    """True when an AWDL window is open (mode is not `off`, something remains, and the
    radio half is still up)."""
    if not isinstance(doc, dict):
        return None
    mode = doc.get("mode")
    if mode in (None, "off") or doc.get("receiving") is False:
        return False
    if doc.get("remaining") is not None and doc.get("remaining") <= 0:
        return False
    if radio_collapsed(doc):
        return False
    return True


def remaining(doc):
    return (doc or {}).get("remaining")


def start(duration=None, timeout=TOOL_TIMEOUT, ensure_bluetooth=True):
    """`omdrop on [duration]` → (ok, message)."""
    if ensure_bluetooth:
        from . import bluetooth
        bluetooth.ensure_started()
    args = ["on"] + ([str(duration)] if duration else [])
    rc, out, err = _run(args, timeout=timeout)
    return rc == 0, (out.strip() or err.strip() or ("omdrop on rc=%d" % rc))

def stop(timeout=4.0, force=False):
    """`omdrop off [--force]` → (ok, message). `--force` is what omdrop's own window
    timers pass: nobody is there to confirm cutting off a send."""
    rc, out, err = _run(["off"] + (["--force"] if force else []), timeout=timeout)
    return rc == 0, (out.strip() or err.strip() or ("omdrop off rc=%d" % rc))
