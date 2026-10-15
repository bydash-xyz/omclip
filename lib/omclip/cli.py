"""`omclip` command line: the frozen contract v1 (see docs/status-schema.md).

Rules that the plugin is written against:

* Every `--json` command prints exactly one JSON object on stdout and exits 0 — a
  stopped or missing daemon is not an error.
* Mutating commands print `{"ok":true, …}` / `{"ok":false,"error":"…"}` and exit 1 on
  failure.
* Human mode: prose on stdout, errors on stderr, exit 1.
* `status` never opens a peer connection and returns in well under 3 s.
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time

from . import VERSION
from . import clipboard
from . import credentials
from . import duration as durationmod
from . import log as logmod
from . import paths
from . import settings as settingsmod
from . import state
from . import status as statusmod

PROG = "omclip"

EXIT_OK = 0
EXIT_FAIL = 1


# --------------------------------------------------------------------------
# small helpers
# --------------------------------------------------------------------------

def repo_root():
    return os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))


def _emit_json(doc, stream=None):
    stream = stream or sys.stdout
    stream.write(json.dumps(doc, sort_keys=False) + "\n")
    stream.flush()


def _fail(message, as_json):
    if as_json:
        _emit_json({"ok": False, "error": message})
    else:
        print("%s: %s" % (PROG, message), file=sys.stderr)
    return EXIT_FAIL


def _ok(doc, as_json, prose=None):
    if as_json:
        _emit_json(doc)
    elif prose:
        print(prose)
    return EXIT_OK


def _systemctl(*args, timeout=15.0):
    binary = shutil.which("systemctl") or "/usr/bin/systemctl"
    try:
        proc = subprocess.run([binary, "--user"] + list(args), capture_output=True,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError) as exc:
        return 127, "", str(exc)
    return (proc.returncode, proc.stdout.decode("utf-8", "replace").strip(),
            proc.stderr.decode("utf-8", "replace").strip())


def service_active():
    return statusmod.unit_state() in ("active", "activating", "reloading")


def load_settings():
    values, warnings = settingsmod.load()
    return settingsmod.Settings(values, warnings)


#: Every `on` mirrors both peers: the Mac over the LAN and the iPhone over AWDL.
#: There is deliberately no way to select one of them — the daemon's job is to
#: keep both in sync, and a half-scoped run only produced a second, invisible
#: device entry for the same machine.
SCOPE = ["mac", "phone"]


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------

def cmd_on(args):
    settings = load_settings()
    scope = list(SCOPE)
    try:
        canonical, seconds, once = durationmod.parse_duration(
            args.duration if args.duration is not None else settings["duration"])
    except ValueError as exc:
        return _fail(str(exc), args.json)
    desired = {"scope": scope, "duration": canonical, "once": once,
               "requested_at": int(time.time())}
    state.save_desired(desired)
    action = "restart" if service_active() else "start"
    rc, out, err = _systemctl(action, paths.UNIT_NAME)
    if rc != 0:
        return _fail("systemctl --user %s %s failed: %s"
                     % (action, paths.UNIT_NAME, err or out or ("rc=%d" % rc)), args.json)
    starting_doc = statusmod.build(daemon_doc=False, settings=settings, desired=desired, unit="active")
    starting_doc["heartbeat"] = int(time.time())
    starting_doc["stale"] = False
    try:
        statusmod.write(starting_doc)
    except OSError:
        pass
    doc = {"ok": True, "on": True, "action": action, "scope": scope,
           "duration": canonical, "unit": paths.UNIT_NAME,
           "expires_in_s": None if once else seconds}
    prose = ("omclip on — scope %s, duration %s%s"
             % (",".join(scope), canonical, " (stops after the first mirror)" if once else ""))
    return _ok(doc, args.json, prose)


def cmd_off(args):
    settings = load_settings()
    state.save_desired({"scope": settings.scopes(), "duration": "off", "once": False,
                        "requested_at": int(time.time())})
    state.clear_desired()
    rt = state.load_runtime()
    was = service_active()
    rc, out, err = _systemctl("stop", paths.UNIT_NAME)
    if rc != 0 and was:
        return _fail("systemctl --user stop %s failed: %s"
                     % (paths.UNIT_NAME, err or out or ("rc=%d" % rc)), args.json)
    if not was:
        if rt.get("omdrop_owned"):
            from . import omdrop
            omdrop.stop()
        if rt.get("bluetooth_owned"):
            from . import bluetooth
            bluetooth.stop()
        state.clear_runtime()
    off_doc = statusmod.build(daemon_doc=False, settings=settings, unit="inactive")
    off_doc["heartbeat"] = int(time.time())
    off_doc["stale"] = False
    try:
        statusmod.write(off_doc)
    except OSError:
        pass
    return _ok({"ok": True, "on": False, "unit": paths.UNIT_NAME, "was_active": was},
               args.json, "omclip off — clipboard left alone, AWDL window released if we "
                          "opened it")


def cmd_toggle(args):
    if service_active():
        return cmd_off(args)
    return cmd_on(args)


def cmd_status(args):
    settings = load_settings()
    desired = state.load_desired()
    doc = statusmod.build(settings=settings, desired=desired)
    if args.json:
        return _ok(doc, True)
    print(_prose_status(doc, settings))
    return EXIT_OK


def cmd_peers(args):
    settings = load_settings()
    doc = statusmod.build(settings=settings, desired=state.load_desired())
    if args.json:
        return _ok({"peers": doc["peers"]}, True)
    for item in doc["peers"]:
        print(_prose_peer(item))
    return EXIT_OK


def cmd_doctor(args):
    settings = load_settings()
    doc = statusmod.build(settings=settings, desired=state.load_desired())
    checks = _doctor_checks(settings, doc)
    ok = all(check["status"] != "fail" for check in checks)
    if args.json:
        return _ok({"ok": ok, "checks": checks}, True)
    for check in checks:
        print("%-4s %-22s %s" % (check["status"].upper(), check["name"], check["detail"]))
    return EXIT_OK if ok else EXIT_FAIL


def cmd_log(args):
    lines = logmod.tail(paths.LOG_FILE, args.n)
    if args.json:
        _emit_json({"lines": lines})
    else:
        for line in lines:
            print(line)
    if not args.follow:
        return EXIT_OK
    path = paths.LOG_FILE
    offset = _file_size(path)
    try:
        while True:
            time.sleep(0.5)
            size = _file_size(path)
            if size < offset:                     # rotated
                offset = 0
            if size == offset:
                continue
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    fh.seek(offset)
                    chunk = fh.read()
            except OSError:
                continue
            offset = size
            new = [line for line in chunk.splitlines() if line.strip()]
            if args.json:
                _emit_json({"lines": new})
            else:
                for line in new:
                    print(line, flush=True)
    except KeyboardInterrupt:
        return EXIT_OK


def cmd_config(args):
    settings = load_settings()
    action = args.action or "list"
    path = paths.SETTINGS_FILE

    if action == "list":
        values = settings.as_dict()
        if args.json:
            return _ok({"settings": values}, True)
        for key, value in values.items():
            print("%s=%s" % (key, _format_value(value)))
        for warning in settings.warnings:
            print("warning: %s" % warning, file=sys.stderr)
        return EXIT_OK

    if action == "get":
        if not args.key:
            return _fail("config get needs a KEY", args.json)
        if args.key not in settingsmod.DEFAULTS:
            return _fail("unknown setting %r" % args.key, args.json)
        value = settings[args.key]
        if args.json:
            return _ok({"settings": {args.key: value}}, True)
        print(_format_value(value))
        return EXIT_OK

    if action == "set":
        if not args.key or args.value is None:
            return _fail("config set needs a KEY and a VALUE", args.json)
        if args.key not in settingsmod.DEFAULTS:
            return _fail("unknown setting %r" % args.key, args.json)
        ok, coerced, error = settingsmod.validate(args.key, args.value)
        if not ok:
            return _fail("%s=%r: %s" % (args.key, args.value, error), args.json)
        values, warnings = settingsmod.load(path)
        values[args.key] = coerced
        settingsmod.write(values, path)
        for warning in warnings:
            print("warning: %s" % warning, file=sys.stderr)
        doc = {"ok": True, "key": args.key, "value": coerced, "file": path}
        return _ok(doc, args.json, "%s=%s" % (args.key, _format_value(coerced)))

    return _fail("unknown config action %r" % action, args.json)


def cmd_version(args):
    if getattr(args, "json", False):
        return _ok({"version": VERSION, "schema": statusmod.SCHEMA}, True)
    print("%s %s" % (PROG, VERSION))
    return EXIT_OK


def cmd_install(args):
    template = os.path.join(repo_root(), "share", "omclip.service")
    entry = os.path.join(repo_root(), "bin", "omclip")
    if not os.path.exists(template):
        return _fail("unit template missing: %s" % template, args.json)
    if not os.path.exists(entry):
        return _fail("entry point missing: %s" % entry, args.json)
    try:
        os.chmod(entry, 0o755)
        paths.ensure_dir(paths.SYSTEMD_USER_DIR)
        shutil.copyfile(template, paths.UNIT_FILE)
        paths.ensure_dir(paths.BIN_DIR)
        if os.path.islink(paths.BIN_LINK) or not os.path.exists(paths.BIN_LINK):
            if os.path.islink(paths.BIN_LINK):
                os.unlink(paths.BIN_LINK)
            os.symlink(entry, paths.BIN_LINK)
        else:
            return _fail("%s exists and is not a symlink; refusing to overwrite"
                         % paths.BIN_LINK, args.json)
    except OSError as exc:
        return _fail("install failed: %s" % exc, args.json)
    rc, _out, err = _systemctl("daemon-reload")
    doc = {"ok": True, "unit": paths.UNIT_FILE, "symlink": paths.BIN_LINK,
           "target": entry, "daemon_reload": "ok" if rc == 0 else (err or "rc=%d" % rc)}
    return _ok(doc, args.json,
               "installed %s and %s -> %s\nnot enabled at boot: `omclip on` starts it"
               % (paths.UNIT_FILE, paths.BIN_LINK, entry))


def cmd_uninstall(args):
    was = service_active()
    if was:
        _systemctl("stop", paths.UNIT_NAME)
    _systemctl("disable", paths.UNIT_NAME)
    removed = []
    for path in (paths.UNIT_FILE, paths.BIN_LINK):
        try:
            if os.path.islink(path) or os.path.exists(path):
                os.unlink(path)
                removed.append(path)
        except OSError as exc:
            return _fail("could not remove %s: %s" % (path, exc), args.json)
    rc, _out, err = _systemctl("daemon-reload")
    state.clear_desired()
    doc = {"ok": True, "removed": removed, "stopped": was,
           "daemon_reload": "ok" if rc == 0 else (err or "rc=%d" % rc),
           "kept": [paths.CONFIG_DIR, paths.STATE_DIR]}
    return _ok(doc, args.json,
               "removed %s\nkept %s and %s (delete them by hand if you want a clean slate)"
               % (", ".join(removed) or "nothing", paths.CONFIG_DIR, paths.STATE_DIR))


def cmd_daemon(args):
    from .daemon import run_daemon
    return run_daemon(load_settings())


# --------------------------------------------------------------------------
# prose rendering
# --------------------------------------------------------------------------

def _format_value(value):
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _ago(stamp):
    if not stamp:
        return "never"
    seconds = max(0, int(time.time() - stamp))
    if seconds < 60:
        return "%ds ago" % seconds
    if seconds < 3600:
        return "%dm%02ds ago" % (seconds // 60, seconds % 60)
    return "%dh%02dm ago" % (seconds // 3600, (seconds % 3600) // 60)


def _prose_peer(item):
    gen = item.get("last_generation") or {}
    detail = ""
    if gen.get("digest"):
        detail = "  last %s %s%s" % (
            (gen.get("digest") or "")[:12], gen.get("uti"),
            " mirrored" if gen.get("mirrored") else
            " skipped: %s" % gen.get("reason"))
    elif gen.get("reason"):
        detail = "  last skipped: %s%s" % (gen.get("reason"),
                                           " (deferred payload %s)"
                                           % statusmod.format_bytes(gen.get("bytes"))
                                           if gen.get("bulk") else "")
    where = "%s:%s" % (item.get("address") or "-", item.get("port") or "-")
    line = "%-6s %-13s %-4s %-24s %s" % (item["key"], item["state"], item["transport"],
                                         where, item["label"])
    if item.get("detail"):
        line += "  — %s" % item["detail"]
    elif item.get("last_error"):
        line += "  — last error: %s" % item["last_error"]
    elif detail:
        line += detail
    line += "  (attempts %s, seen %s)" % (item.get("attempts"), _ago(item.get("last_seen")))
    return line


def _prose_status(doc, settings):
    out = []
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(doc["since"])) if doc["since"] \
        else "-"
    left = ("forever" if doc["expires_at"] is None
            else durationmod.format_seconds(doc["seconds_left"]))
    out.append("%s %s — state %s%s" % (PROG, doc["version"], doc["state"],
                                       "  (stale: no heartbeat)" if doc["stale"] else ""))
    out.append("  scope:      %s   duration: %s   since: %s   left: %s"
               % (",".join(doc["scope"]), doc["duration"], since, left))
    inst = doc["instance"]
    out.append("  unit:       %s (%s) pid %s rss %s kB uptime %s s"
               % (inst["unit"], inst["unit_state"], inst["pid"], inst["rss_kb"],
                  inst["uptime_s"]))
    out.append("  peers:")
    for item in doc["peers"]:
        out.append("    " + _prose_peer(item))
    clip = doc["clipboard"]
    skipped = clip.get("skipped") or {}
    last_file = clip.get("last_file") or {}
    if not clip.get("last_uti"):
        last = ""
    elif last_file.get("path"):
        # A file mirror: the file's name, its own size and where it landed. The clipboard
        # holds a `file://` URI (48 bytes for this copy); that length is never shown, and
        # never as if it were the size of the file.
        last = " (file %s, %s, %s)" % (last_file.get("name"),
                                       statusmod.format_bytes(last_file.get("bytes")),
                                       last_file["path"])
    else:
        last = " (%s, %s)" % (clip.get("last_uti"),
                              statusmod.format_bytes(clip.get("last_bytes")))
    out.append("  clipboard:  %s mirrored, last %s%s"
               % (clip.get("mirrored_total"), _ago(clip.get("last_mirrored_at")), last))
    out.append("              skipped: " + " ".join(
        "%s=%s" % (key, skipped.get(key, 0)) for key in statusmod.SKIP_REASONS))
    health = doc["health"]
    out.append("  health:     bluetooth %s%s | awdl %s | omdrop %s%s | wl-clipboard %s | "
               "wayland %s | ble %s | crypto %s"
               % (health["bluetooth"],
                  " (%s)" % health["bluetooth_detail"] if health["bluetooth_detail"] else "",
                  health["awdl"], health["omdrop"],
                  " (owned by omclip)" if health["omdrop_owned"] else "",
                  "yes" if health["wl_clipboard"] else "no",
                  "yes" if health["wayland"] else "no",
                  health.get("ble_backend", "unknown"),
                  health.get("crypto_backend", "unknown")))
    if health.get("ble_detail"):
        out.append("              ble: %s" % health["ble_detail"])
    if health.get("crypto_detail"):
        out.append("              crypto: %s" % health["crypto_detail"])
    for cred in doc["credentials"]:
        out.append("  credential: %-14s %-8s %s%s"
                   % (cred["kind"], cred["status"], cred["file"],
                      " (%s days)" % cred["days_left"] if cred["days_left"] is not None else ""))
    out.append("  errors:     %s" % ("; ".join(doc["errors"]) if doc["errors"] else "none"))
    for warning in settings.warnings:
        out.append("  settings:   %s" % warning)
    return "\n".join(out)


# --------------------------------------------------------------------------
# doctor
# --------------------------------------------------------------------------

def _check(name, status, detail):
    return {"name": name, "status": status, "detail": detail}


def _doctor_checks(settings, doc):
    checks = []
    wayland = clipboard.wayland_available()
    wl_copy, wl_paste = clipboard.tool("wl-copy"), clipboard.tool("wl-paste")
    checks.append(_check("wayland", "ok" if wayland else "fail",
                         "WAYLAND_DISPLAY=%s" % (os.environ.get("WAYLAND_DISPLAY") or "-")))
    checks.append(_check("wl-clipboard", "ok" if (wl_copy and wl_paste) else "fail",
                         "wl-copy=%s wl-paste=%s" % (wl_copy or "-", wl_paste or "-")))
    identity = os.path.join(settings["identity_dir"], "rapport_identity.json")
    ids = os.path.join(settings["identity_dir"], "rapport_ids.json")
    if os.path.exists(identity) and os.path.exists(ids):
        checks.append(_check("identity", "ok", settings["identity_dir"]))
    else:
        checks.append(_check("identity", "fail",
                             "missing %s — %s"
                             % (identity if not os.path.exists(identity) else ids,
                                credentials.REFRESH_HINT)))
    for cred in credentials.check(settings["keys_dir"], settings["identity_dir"]):
        status = {"ok": "ok", "warn": "warn", "expired": "fail", "missing": "warn",
                  "unknown": "warn"}[cred.status]
        checks.append(_check("cred:%s" % cred.kind, status,
                             "%s (%s%s)" % (cred.file, cred.status,
                                            ", %s days" % cred.days_left
                                            if cred.days_left is not None else "")))
    health = doc["health"]
    checks.append(_check("bluetooth", {"ok": "ok", "off": "warn", "wedged": "fail",
                                       "unknown": "warn"}[health["bluetooth"]],
                         health["bluetooth_detail"] or health["bluetooth"]))
    checks.append(_check("ble-trigger",
                         "ok" if health.get("ble_backend") == "monitor" else "warn",
                         health.get("ble_detail") or health.get("ble_backend", "unknown")))
    # The pure-python AEAD is a working but ~80x-the-CPU state, not a broken one: warn,
    # never fail, and say which reason the crypto module recorded.
    checks.append(_check("crypto-aead",
                         "ok" if health.get("crypto_backend") == "libcrypto" else "warn",
                         health.get("crypto_detail") or health.get("crypto_backend", "unknown")))
    checks.append(_check("awdl0", "ok" if health["awdl"] == "up" else "warn",
                         "awdl %s%s" % (health["awdl"],
                                        "" if health["awdl"] == "up"
                                        else " — the iPhone needs `omdrop on <duration>`")))
    checks.append(_check("omdrop", "ok" if health["omdrop"] == "on" else "warn",
                         "omdrop %s%s" % (health["omdrop"],
                                          " (owned by omclip)" if health["omdrop_owned"]
                                          else "")))
    unit_ok = os.path.exists(paths.UNIT_FILE)
    checks.append(_check("unit", "ok" if unit_ok else "warn",
                         paths.UNIT_FILE if unit_ok else
                         "not installed — run `omclip install`"))
    link_ok = os.path.islink(paths.BIN_LINK)
    checks.append(_check("symlink", "ok" if link_ok else "warn",
                         paths.BIN_LINK if link_ok else
                         "not installed — run `omclip install`"))
    for warning in settings.warnings:
        checks.append(_check("settings", "warn", warning))
    if doc["stale"]:
        checks.append(_check("daemon", "fail",
                             "unit active but no heartbeat for >10 s (see `omclip log`)"))
    elif doc["instance"]["unit_state"] == "active":
        checks.append(_check("daemon", "ok", "pid %s, state %s" % (doc["instance"]["pid"],
                                                                   doc["state"])))
    else:
        checks.append(_check("daemon", "warn", "not running (start with `omclip on`)"))
    return checks


def _file_size(path):
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------

def build_parser():
    parser = argparse.ArgumentParser(
        prog=PROG,
        description="Apple Universal Clipboard (continuity pasteboard) mirror for "
                    "Omarchy — direct to each Apple device, no relay. Every run "
                    "mirrors both the Mac and the iPhone; there is no scope switch.")
    parser.add_argument("--version", action="version", version="%s %s" % (PROG, VERSION))
    sub = parser.add_subparsers(dest="command")

    p_on = sub.add_parser("on", help="start mirroring (default: until `omclip off`)")
    p_on.add_argument("duration", nargs="?", default=None,
                      help="10 (minutes), 30s, 10m, 1h, forever (default), once")
    p_on.add_argument("--json", action="store_true")
    p_on.set_defaults(func=cmd_on)

    p_off = sub.add_parser("off", help="stop mirroring and release the AWDL window we opened")
    p_off.add_argument("--json", action="store_true")
    p_off.set_defaults(func=cmd_off)

    p_toggle = sub.add_parser("toggle", help="on if off, off if on")
    p_toggle.add_argument("duration", nargs="?", default=None)
    p_toggle.add_argument("--json", action="store_true")
    p_toggle.set_defaults(func=cmd_toggle)

    p_status = sub.add_parser("status", help="state, peers, clipboard, health, credentials")
    p_status.add_argument("--json", action="store_true")
    p_status.set_defaults(func=cmd_status)

    p_peers = sub.add_parser("peers", help="peer table only")
    p_peers.add_argument("--json", action="store_true")
    p_peers.set_defaults(func=cmd_peers)

    p_doctor = sub.add_parser("doctor", help="diagnose setup and radio state")
    p_doctor.add_argument("--json", action="store_true")
    p_doctor.set_defaults(func=cmd_doctor)

    p_log = sub.add_parser("log", help="recent daemon log lines")
    p_log.add_argument("-n", type=int, default=20)
    p_log.add_argument("--json", action="store_true")
    p_log.add_argument("--follow", action="store_true")
    p_log.set_defaults(func=cmd_log)

    p_config = sub.add_parser("config", help="list / get / set settings")
    p_config.add_argument("action", nargs="?", default="list",
                          choices=["list", "get", "set"])
    p_config.add_argument("key", nargs="?")
    p_config.add_argument("value", nargs="?")
    p_config.add_argument("--json", action="store_true")
    p_config.set_defaults(func=cmd_config)

    p_install = sub.add_parser("install", help="install the user unit and the bin symlink")
    p_install.add_argument("--json", action="store_true")
    p_install.set_defaults(func=cmd_install)

    p_uninstall = sub.add_parser("uninstall", help="remove the unit and the bin symlink")
    p_uninstall.add_argument("--json", action="store_true")
    p_uninstall.set_defaults(func=cmd_uninstall)

    p_version = sub.add_parser("version", help="print the version")
    p_version.add_argument("--json", action="store_true")
    p_version.set_defaults(func=cmd_version)

    p_daemon = sub.add_parser("daemon", help="internal: what omclip.service runs")
    p_daemon.set_defaults(func=cmd_daemon)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        parser.print_help()
        return EXIT_OK
    if not hasattr(args, "json"):
        args.json = False
    try:
        return args.func(args)
    except KeyboardInterrupt:
        return EXIT_OK
    except BrokenPipeError:
        return EXIT_OK
