"""The `status` document: schema 1, assembled and validated in one place.

Two rules shape this module:

* `omclip status` must work with **no daemon** and must **never open a peer
  connection**: the daemon's own view is read from `status.json` (written at ≥ 1 Hz),
  while health and credentials are probed live on every call. That keeps `status`
  honest when the daemon is stale and keeps it well under the 3 s budget.
* A stopped or missing daemon is not an error. State is `off`, every peer is
  `disabled`, exit code 0.

`stale` is true when the unit reports active but the daemon's heartbeat is older than
10 s — the panel can then show "not reporting" instead of a cheerful lie.
"""

import os
import time

from . import VERSION, credentials, clipboard, discovery, omdrop, paths, peer as peermod
from .bluetooth import probe as bt_probe
from .state import read_json, write_json

SCHEMA = 1
HEARTBEAT_STALE_S = 10.0
UNIT_NAME = paths.UNIT_NAME

STATES = ("off", "starting", "on", "degraded", "error")

SKIP_REASONS = ("unchanged", "bulk", "empty", "local_echo", "oversize", "nodata")

HEALTH_BLUETOOTH = ("ok", "off", "wedged", "unknown")
HEALTH_AWDL = ("up", "down", "unknown")
HEALTH_OMDROP = ("on", "off", "unknown")
HEALTH_BLE = ("monitor", "unavailable", "unknown")
HEALTH_CRYPTO = ("libcrypto", "python", "unknown")


# --------------------------------------------------------------------------
# systemd / process facts
# --------------------------------------------------------------------------

def _systemctl(*args, timeout=3.0):
    binary = "/usr/bin/systemctl"
    if not os.path.exists(binary):
        binary = "systemctl"
    import subprocess
    try:
        proc = subprocess.run([binary, "--user"] + list(args), capture_output=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return 1, ""
    return proc.returncode, proc.stdout.decode("utf-8", "replace").strip()


def unit_state(name=UNIT_NAME):
    """systemd's view: active | inactive | failed | activating | … | unknown."""
    rc, out = _systemctl("is-active", name, timeout=2.0)
    if rc == 0 and out:
        return out.splitlines()[0].strip()
    if out:
        return out.splitlines()[0].strip()
    return "unknown"


def main_pid(name=UNIT_NAME):
    rc, out = _systemctl("show", "-p", "MainPID", "--value", name, timeout=2.0)
    if rc != 0 or not out.strip().isdigit():
        return None
    pid = int(out.strip())
    return pid or None


def proc_rss_kb(pid):
    try:
        with open("/proc/%d/status" % pid, "r", encoding="utf-8") as fh:
            for line in fh:
                if line.startswith("VmRSS:"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def proc_uptime_s(pid, now=None):
    """Seconds since the process started (from /proc/<pid>/stat starttime + btime)."""
    try:
        with open("/proc/%d/stat" % pid, "r", encoding="utf-8") as fh:
            fields = fh.read().rsplit(")", 1)[1].split()
        start_ticks = int(fields[19])
    except (OSError, ValueError, IndexError):
        return None
    try:
        with open("/proc/stat", "r", encoding="utf-8") as fh:
            btime = next(int(line.split()[1]) for line in fh if line.startswith("btime "))
    except (OSError, ValueError, StopIteration):
        return None
    ticks = os.sysconf("SC_CLK_TCK") or 100
    started = btime + start_ticks / ticks
    return int((now or time.time()) - started)


# --------------------------------------------------------------------------
# live probes
# --------------------------------------------------------------------------

def live_health(settings=None):
    """bluetooth / awdl / omdrop / clipboard facts, probed live (cheap, read-only)."""
    settings = settings or {}
    bt = bt_probe()
    doc = omdrop.status()
    awdl = discovery.awdl_up()
    return {
        "bluetooth": bt.status,
        "bluetooth_detail": bt.detail,
        "awdl": "unknown" if awdl is None else ("up" if awdl else "down"),
        "omdrop": "unknown" if doc is None else ("on" if omdrop.window_active(doc) else "off"),
        "omdrop_owned": False,
        "bluetooth_owned": False,
        "wl_clipboard": bool(clipboard.tool("wl-copy") and clipboard.tool("wl-paste")),
        "wayland": clipboard.wayland_available(),
        # ble_backend / crypto_backend are decided by the *daemon's* process, not this
        # one; `build()` fills both in from the daemon's own document when it runs.
        "ble_backend": "unknown",
        "ble_detail": None,
        "crypto_backend": "unknown",
        "crypto_detail": None,
    }


def credentials_doc(settings=None):
    settings = settings or {}
    keys_dir = settings.get("keys_dir") or paths.DEFAULT_KEYS_DIR
    identity_dir = settings.get("identity_dir") or paths.DEFAULT_IDENTITY_DIR
    return [c.as_dict() for c in credentials.check(keys_dir, identity_dir)]


# --------------------------------------------------------------------------
# human formatting
# --------------------------------------------------------------------------

def format_bytes(count):
    """A byte count in the units a person reads: `999 B`, `312.9 kB`, `1.6 MB`.

    Decimal units (1000-based), matching the README's own prose — the 2 000 000-byte
    AppleArchive test copy is "2 MB" there. `None` becomes `?`, so a caller can print a
    size it does not know without special-casing it.
    """
    if count is None:
        return "?"
    count = int(count)
    if count < 1000:
        return "%d B" % count
    if count < 1000000:
        return "%.1f kB" % (count / 1000.0)
    if count < 1000000000:
        return "%.1f MB" % (count / 1000000.0)
    return "%.1f GB" % (count / 1000000000.0)


# --------------------------------------------------------------------------
# document assembly
# --------------------------------------------------------------------------

def blank_peers(state="disabled", scope=("mac", "phone")):
    """Both peer objects in the frozen order, forced to `state`."""
    out = []
    for key in peermod.ORDER:
        item = peermod.Peer(key, in_scope=(key in scope)).to_status()
        item["state"] = state
        item["detail"] = None if key in scope else "not in scope"
        out.append(item)
    return out


def consolidate_peers(peers):
    """Ensure each physical Apple device appears at most once in status.peers.

    If the Mac appears under both 'mac' and 'phone' (e.g. LAN IPv4 and AWDL IPv6),
    consolidate them: keep the Mac peer with its primary LAN transport/address,
    and restore the phone peer to an honest unreachable state representing the iPhone.
    """
    if not peers or not isinstance(peers, list):
        return peers
    mac_peer = next((p for p in peers if p.get("key") == "mac"), None)
    phone_peer = next((p for p in peers if p.get("key") == "phone"), None)
    if mac_peer and phone_peer:
        mac_label = (mac_peer.get("label") or "").strip().lower()
        phone_label = (phone_peer.get("label") or "").strip().lower()
        is_dup = False
        if mac_label and phone_label and mac_label == phone_label:
            is_dup = True
        elif "mac" in phone_label or "macbook" in phone_label:
            is_dup = True
        elif phone_peer.get("port") == 49152:
            is_dup = True
        elif mac_peer.get("address") and phone_peer.get("address") and mac_peer.get("address") == phone_peer.get("address"):
            is_dup = True
        if is_dup:
            phone_peer["label"] = peermod.DEFAULT_LABELS["phone"]
            phone_peer["state"] = "unreachable"
            phone_peer["detail"] = "iPhone not detected (MacBook Pro detected on AWDL)"
            phone_peer["address"] = None
            phone_peer["port"] = None
            phone_peer["last_seen"] = None
            phone_peer["attempts"] = 0
            phone_peer["last_error"] = None
            phone_peer["last_generation"] = peermod.blank_generation()
    return peers


def build(daemon_doc=None, settings=None, *, now=None, probe_live=True, desired=None,
          unit=None):
    """Assemble the schema-1 status document."""
    now = time.time() if now is None else now
    settings = settings or {}
    scope = settings.get("scope_list") or settings.get("scope") or ["mac", "phone"]
    if isinstance(scope, str):
        scope = [scope] if scope != "both" else ["mac", "phone"]
    unit = unit or unit_state()
    if daemon_doc is None:
        daemon_doc = read_json(paths.STATUS_FILE)
    active = unit in ("active", "activating", "reloading")

    daemon_running = (
        active
        and isinstance(daemon_doc, dict)
        and daemon_doc.get("on") is True
        and daemon_doc.get("state") != "off"
    )

    if daemon_running:
        state = daemon_doc.get("state", "starting")
        on = bool(daemon_doc.get("on"))
        since = daemon_doc.get("since")
        expires_at = daemon_doc.get("expires_at")
        duration = daemon_doc.get("duration") or (settings.get("duration") or "forever")
        peers = consolidate_peers(daemon_doc.get("peers") or blank_peers(scope=scope))
        clip = daemon_doc.get("clipboard")
        errors = list(daemon_doc.get("errors") or [])
        heartbeat = daemon_doc.get("heartbeat")
        started_at = daemon_doc.get("started_at")
        pid = daemon_doc.get("pid")
        scope = daemon_doc.get("scope") or scope
    else:
        # No daemon (or none yet): honest zero state, peers disabled, nothing probed
        # beyond the live health/credential facts below.
        starting = active
        state = "starting" if starting else "off"
        on = starting
        since = expires_at = None
        duration = (desired or {}).get("duration") or settings.get("duration") or "forever"
        peers = blank_peers(state="disabled", scope=scope)
        if starting:
            for item in peers:
                if item["key"] in scope:
                    item["state"] = "resolving"
                    item["detail"] = "waiting for the daemon's first status write"
        clip = {"mirrored_total": 0, "last_mirrored_at": None, "last_digest": None,
                "last_uti": None, "last_bytes": None, "last_file": None,
                "last_preview": None,
                "skipped": {reason: 0 for reason in SKIP_REASONS}}
        errors = []
        heartbeat = None
        started_at = None
        pid = None

    stale = bool(active and (heartbeat is None or now - float(heartbeat or 0) > HEARTBEAT_STALE_S))
    seconds_left = None
    if expires_at:
        seconds_left = max(0, int(round(float(expires_at) - now)))

    if pid is None and active:
        pid = main_pid()
    instance = {
        "pid": pid,
        "rss_kb": proc_rss_kb(pid) if pid else None,
        "uptime_s": (int(now - started_at) if started_at else
                     (proc_uptime_s(pid, now) if pid else None)),
        "unit": UNIT_NAME,
        "unit_state": unit,
    }

    health = live_health(settings) if probe_live else {
        "bluetooth": "unknown", "bluetooth_detail": None, "awdl": "unknown",
        "omdrop": "unknown", "omdrop_owned": False, "bluetooth_owned": False,
        "wl_clipboard": False,
        "wayland": False, "ble_backend": "unknown", "ble_detail": None,
        "crypto_backend": "unknown", "crypto_detail": None,
    }
    if isinstance(daemon_doc, dict) and active:
        # The daemon owns the AWDL window and bluetooth, so its record is the truth for ownership.
        health["omdrop_owned"] = bool(daemon_doc.get("omdrop_owned"))
        if "bluetooth_owned" in daemon_doc:
            health["bluetooth_owned"] = bool(daemon_doc.get("bluetooth_owned"))
        elif "bluetooth_owned" in (daemon_doc.get("health") or {}):
            health["bluetooth_owned"] = bool(daemon_doc["health"]["bluetooth_owned"])
        if daemon_doc.get("ble_backend"):
            health["ble_backend"] = daemon_doc["ble_backend"]
            health["ble_detail"] = daemon_doc.get("ble_detail")
        if daemon_doc.get("crypto_backend"):
            health["crypto_backend"] = daemon_doc["crypto_backend"]
            health["crypto_detail"] = daemon_doc.get("crypto_detail")

    return {
        "schema": SCHEMA,
        "version": VERSION,
        "state": state,
        "on": on,
        "since": since,
        "expires_at": expires_at,
        "seconds_left": seconds_left,
        "scope": list(scope),
        "duration": duration,
        "stale": stale,
        "instance": instance,
        "peers": peers,
        "clipboard": clip,
        "health": health,
        "credentials": credentials_doc(settings) if probe_live else [],
        "errors": errors,
    }


# --------------------------------------------------------------------------
# persistence
# --------------------------------------------------------------------------

def write(doc, path=None):
    """Atomic status write (tmp + os.replace) — called at ≥ 1 Hz by the daemon."""
    return write_json(path or paths.STATUS_FILE, doc)


def read(path=None):
    doc = read_json(path or paths.STATUS_FILE)
    return doc if isinstance(doc, dict) else None


# --------------------------------------------------------------------------
# schema conformance (used by the tests and `doctor`)
# --------------------------------------------------------------------------

def _is_int_or_null(value):
    return value is None or (isinstance(value, int) and not isinstance(value, bool))


def validate(doc):
    """Return a list of schema violations (empty = conforms to frozen contract v1)."""
    problems = []

    def expect(cond, message):
        if not cond:
            problems.append(message)

    expect(isinstance(doc, dict), "document is not an object")
    if not isinstance(doc, dict):
        return problems

    expect(doc.get("schema") == SCHEMA, "schema must be %d" % SCHEMA)
    expect(isinstance(doc.get("version"), str) and doc["version"], "version must be a string")
    expect(doc.get("state") in STATES, "state must be one of %s" % (STATES,))
    expect(isinstance(doc.get("on"), bool), "on must be a bool")
    expect(_is_int_or_null(doc.get("since")), "since must be epoch seconds or null")
    expect(_is_int_or_null(doc.get("expires_at")), "expires_at must be epoch seconds or null")
    expect(_is_int_or_null(doc.get("seconds_left")), "seconds_left must be int or null")
    expect(isinstance(doc.get("scope"), list) and doc["scope"], "scope must be a non-empty list")
    expect(all(item in ("mac", "phone") for item in doc.get("scope", [])),
           "scope entries must be mac/phone")
    expect(isinstance(doc.get("duration"), str), "duration must be a string")
    expect(isinstance(doc.get("stale"), bool), "stale must be a bool")

    instance = doc.get("instance")
    expect(isinstance(instance, dict), "instance must be an object")
    if isinstance(instance, dict):
        for key in ("pid", "rss_kb", "uptime_s"):
            expect(_is_int_or_null(instance.get(key)), "instance.%s must be int or null" % key)
        expect(isinstance(instance.get("unit"), str), "instance.unit must be a string")
        expect(isinstance(instance.get("unit_state"), str),
               "instance.unit_state must be a string")

    peers = doc.get("peers")
    expect(isinstance(peers, list), "peers must be a list")
    for index, item in enumerate(peers if isinstance(peers, list) else []):
        where = "peers[%d]" % index
        expect(isinstance(item, dict), "%s must be an object" % where)
        if not isinstance(item, dict):
            continue
        expect(item.get("key") in ("mac", "phone"), "%s.key must be mac/phone" % where)
        expect(item.get("kind") in ("mac", "iphone", "unknown"), "%s.kind" % where)
        expect(isinstance(item.get("label"), str), "%s.label must be a string" % where)
        expect(item.get("transport") in ("lan", "awdl"), "%s.transport" % where)
        expect(isinstance(item.get("state"), str), "%s.state must be a string" % where)
        expect(item.get("state") in peermod.STATES, "%s.state unknown value" % where)
        expect(_is_int_or_null(item.get("last_seen")), "%s.last_seen" % where)
        expect(_is_int_or_null(item.get("attempts")), "%s.attempts must be an int" % where)
        gen = item.get("last_generation")
        expect(isinstance(gen, dict), "%s.last_generation must be an object" % where)
        if isinstance(gen, dict):
            for key in ("digest", "at", "uti", "bytes", "reason"):
                expect(gen.get(key) is None or isinstance(gen[key], (str, int)),
                       "%s.last_generation.%s" % (where, key))
            expect(isinstance(gen.get("mirrored"), bool), "%s.last_generation.mirrored" % where)
            expect(isinstance(gen.get("bulk"), bool), "%s.last_generation.bulk" % where)

    clip = doc.get("clipboard")
    expect(isinstance(clip, dict), "clipboard must be an object")
    if isinstance(clip, dict):
        expect(_is_int_or_null(clip.get("mirrored_total")), "clipboard.mirrored_total")
        expect(isinstance(clip.get("skipped"), dict), "clipboard.skipped must be an object")
        for reason in SKIP_REASONS:
            expect(isinstance((clip.get("skipped") or {}).get(reason), int),
                   "clipboard.skipped.%s must be an int" % reason)
        # Additive: a document from a build that predates `last_file` still conforms.
        if "last_file" in clip:
            last_file = clip.get("last_file")
            expect(last_file is None or isinstance(last_file, dict),
                   "clipboard.last_file must be an object or null")
            if isinstance(last_file, dict):
                for key in ("name", "path"):
                    expect(isinstance(last_file.get(key), str),
                           "clipboard.last_file.%s must be a string" % key)
                expect(_is_int_or_null(last_file.get("bytes")),
                       "clipboard.last_file.bytes must be int or null")

    health = doc.get("health")
    expect(isinstance(health, dict), "health must be an object")
    if isinstance(health, dict):
        expect(health.get("bluetooth") in HEALTH_BLUETOOTH, "health.bluetooth")
        expect(health.get("awdl") in HEALTH_AWDL, "health.awdl")
        expect(health.get("omdrop") in HEALTH_OMDROP, "health.omdrop")
        expect(isinstance(health.get("omdrop_owned"), bool), "health.omdrop_owned")
        if "bluetooth_owned" in health:
            expect(isinstance(health.get("bluetooth_owned"), bool), "health.bluetooth_owned")
        expect(isinstance(health.get("wayland"), bool), "health.wayland")
        # Additive keys: checked only when a document carries them, so a document from a
        # build that predates them still conforms to v1.
        if "crypto_backend" in health:
            expect(health.get("crypto_backend") in HEALTH_CRYPTO, "health.crypto_backend")
        if "crypto_detail" in health:
            expect(health.get("crypto_detail") is None
                   or isinstance(health.get("crypto_detail"), str), "health.crypto_detail")

    creds = doc.get("credentials")
    expect(isinstance(creds, list), "credentials must be a list")
    for index, item in enumerate(creds if isinstance(creds, list) else []):
        where = "credentials[%d]" % index
        expect(isinstance(item, dict), "%s must be an object" % where)
        if isinstance(item, dict):
            expect(isinstance(item.get("file"), str), "%s.file" % where)
            expect(isinstance(item.get("kind"), str), "%s.kind" % where)
            expect(item.get("status") in ("ok", "warn", "expired", "missing", "unknown"),
                   "%s.status" % where)
    expect(isinstance(doc.get("errors"), list), "errors must be a list")
    expect(all(isinstance(e, str) for e in doc.get("errors", [])), "errors must be strings")
    return problems
