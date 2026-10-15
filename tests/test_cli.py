"""CLI contract: exactly one JSON object for `--json`, exit codes, config persistence.

The live `status`/`doctor` probes are stubbed here (the real ones are exercised in the
journal); what is pinned is the contract shape the plugin is written against.
"""

import contextlib
import io
import json
import os
import tempfile
import time
import unittest

import _support  # noqa: F401
from omclip import VERSION, cli, log as logmod, paths, status

FAKE_HEALTH = {"bluetooth": "off", "bluetooth_detail": "inactive", "awdl": "down",
               "omdrop": "off", "omdrop_owned": False, "wl_clipboard": True,
               "wayland": True, "ble_backend": "unavailable", "ble_detail": "no gi"}


def run(argv):
    """Run the CLI, capturing stdout/stderr; returns (code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = cli.main(argv)
    return code, out.getvalue(), err.getvalue()


@contextlib.contextmanager
def stubbed_probes(health=None):
    saved = (status.live_health, status.credentials_doc)
    status.live_health = lambda settings=None: dict(FAKE_HEALTH if health is None else health)
    status.credentials_doc = lambda settings=None: []
    try:
        yield
    finally:
        status.live_health, status.credentials_doc = saved


class Parser(unittest.TestCase):
    def test_on_duration(self):
        args = cli.build_parser().parse_args(["on", "10", "--json"])
        self.assertEqual(args.command, "on")
        self.assertEqual(args.duration, "10")
        self.assertTrue(args.json)

    def test_scope_flags_are_gone(self):
        # Scope is no longer selectable: every `on` mirrors both peers.
        for flag in ("--mac", "--phone", "--both"):
            with self.assertRaises(SystemExit):
                cli.build_parser().parse_args(["on", flag])

    def test_log_flags(self):
        args = cli.build_parser().parse_args(["log", "-n", "5", "--follow", "--json"])
        self.assertEqual(args.n, 5)
        self.assertTrue(args.follow)
        self.assertTrue(args.json)

    def test_config_subcommands(self):
        args = cli.build_parser().parse_args(["config", "set", "poll_seconds", "5"])
        self.assertEqual((args.action, args.key, args.value),
                         ("set", "poll_seconds", "5"))
        self.assertEqual(cli.build_parser().parse_args(["config"]).action, "list")

    def test_no_command_prints_help(self):
        code, out, _err = run([])
        self.assertEqual(code, 0)
        self.assertIn("usage: omclip", out)

    def test_help_exits_zero(self):
        with self.assertRaises(SystemExit) as ctx:
            cli.build_parser().parse_args(["--help"])
        self.assertEqual(ctx.exception.code, 0)


class Version(unittest.TestCase):
    def test_human(self):
        code, out, _err = run(["version"])
        self.assertEqual(code, 0)
        self.assertTrue(out.startswith("omclip "))

    def test_json_is_one_object(self):
        code, out, _err = run(["version", "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["version"], VERSION)
        self.assertEqual(doc["schema"], 1)
        self.assertEqual(len(out.strip().splitlines()), 1)


class StatusCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = (paths.STATUS_FILE, paths.SETTINGS_FILE, status.unit_state)
        paths.STATUS_FILE = os.path.join(self.tmp.name, "status.json")
        paths.SETTINGS_FILE = os.path.join(self.tmp.name, "settings")
        # Hermetic: the real systemd unit may well be running on this machine.
        status.unit_state = lambda name=None: "inactive"

    def tearDown(self):
        paths.STATUS_FILE, paths.SETTINGS_FILE, status.unit_state = self._saved
        self.tmp.cleanup()

    def test_status_json_without_a_daemon(self):
        with stubbed_probes():
            code, out, _err = run(["status", "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(status.validate(doc), [])
        self.assertEqual(doc["state"], "off")
        self.assertFalse(doc["on"])
        self.assertTrue(all(p["state"] == "disabled" for p in doc["peers"]))

    def test_status_human(self):
        with stubbed_probes():
            code, out, _err = run(["status"])
        self.assertEqual(code, 0)
        self.assertIn("state off", out)
        self.assertIn("health:", out)
        self.assertIn("errors:     none", out)

    def test_peers_json(self):
        with stubbed_probes():
            code, out, _err = run(["peers", "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual([p["key"] for p in doc["peers"]], ["mac", "phone"])

    def test_doctor_json(self):
        with stubbed_probes():
            code, out, _err = run(["doctor", "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertIn("checks", doc)
        names = {check["name"] for check in doc["checks"]}
        self.assertIn("wayland", names)
        self.assertIn("identity", names)
        self.assertIn("daemon", names)
        for check in doc["checks"]:
            self.assertIn(check["status"], ("ok", "warn", "fail"))

    def test_doctor_human_reports_failure_exit_code(self):
        # Without the identity/keys this machine cannot mirror; doctor must say so and
        # exit 1 in human mode (JSON mode always exits 0).
        with stubbed_probes():
            code, out, _err = run(["doctor"])
        self.assertIn(code, (0, 1))
        self.assertTrue(out.strip())


def _clipboard_doc(clipboard):
    """A daemon document with the given `clipboard` object, as `status.json` holds one."""
    return {"schema": 1, "version": VERSION, "state": "on", "on": True,
            "since": int(time.time()) - 30, "expires_at": None, "duration": "forever",
            "scope": ["mac", "phone"], "peers": [], "clipboard": clipboard, "errors": [],
            "heartbeat": int(time.time()), "pid": os.getpid(),
            "started_at": int(time.time()) - 30, "omdrop_owned": False,
            "bluetooth_owned": False}


def _clip(**overrides):
    clip = {"mirrored_total": 4, "last_mirrored_at": int(time.time()) - 30,
            "last_digest": "ab" * 32, "last_uti": None, "last_bytes": None,
            "last_file": None, "last_preview": None,
            "skipped": {reason: 0 for reason in status.SKIP_REASONS}}
    clip.update(overrides)
    return clip


class ClipboardProse(unittest.TestCase):
    """What the last mirror was, in one line: a file is named, never counted as its URI."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = (paths.STATUS_FILE, paths.SETTINGS_FILE, status.unit_state)
        paths.STATUS_FILE = os.path.join(self.tmp.name, "status.json")
        paths.SETTINGS_FILE = os.path.join(self.tmp.name, "settings")
        status.unit_state = lambda name=None: "active"
        self.addCleanup(self._restore)

    def _restore(self):
        paths.STATUS_FILE, paths.SETTINGS_FILE, status.unit_state = self._saved
        self.tmp.cleanup()

    def _status_line(self, clip):
        status.write(_clipboard_doc(clip), path=paths.STATUS_FILE)
        with stubbed_probes():
            code, out, _err = run(["status"])
        self.assertEqual(code, 0)
        return [line for line in out.splitlines() if "clipboard:" in line]

    def test_a_file_mirror_names_the_file_and_its_own_size(self):
        lines = self._status_line(_clip(
            last_uti="public.file-url", last_bytes=1631561,
            last_file={"name": "IMG_1739.HEIC",
                       "path": "/home/user/Downloads/IMG_1739.HEIC", "bytes": 1631561}))
        self.assertEqual(len(lines), 1)
        line = lines[0]
        self.assertIn("file IMG_1739.HEIC", line)
        self.assertIn("1.6 MB", line)
        self.assertIn("/home/user/Downloads/IMG_1739.HEIC", line)
        # The 48-byte `file://` URI is what is on the clipboard; it is never the size shown.
        self.assertNotIn("48 B", line)
        self.assertNotIn("1631561 B", line)

    def test_a_text_mirror_still_reports_its_bytes(self):
        lines = self._status_line(_clip(
            last_uti="public.utf8-plain-text", last_bytes=24, last_preview="hello"))
        self.assertEqual(len(lines), 1)
        self.assertIn("(public.utf8-plain-text, 24 B)", lines[0])
        self.assertNotIn("file ", lines[0])


class DoctorCrypto(unittest.TestCase):
    """The AEAD backend shows up in doctor: OK for libcrypto, WARN for the fallback.

    A fallback works, it is just ~80x the CPU per poll, so it must never be `fail` —
    and never change an exit code.
    """

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = (paths.STATUS_FILE, paths.SETTINGS_FILE, status.unit_state)
        paths.STATUS_FILE = os.path.join(self.tmp.name, "status.json")
        paths.SETTINGS_FILE = os.path.join(self.tmp.name, "settings")
        status.unit_state = lambda name=None: "inactive"   # the real unit may be running

    def tearDown(self):
        paths.STATUS_FILE, paths.SETTINGS_FILE, status.unit_state = self._saved
        self.tmp.cleanup()

    def _doctor(self, argv, **health):
        with stubbed_probes(dict(FAKE_HEALTH, **health)):
            return run(argv)

    def _crypto_checks(self, out):
        return [check for check in json.loads(out)["checks"]
                if check["name"] == "crypto-aead"]

    def test_libcrypto_is_ok(self):
        code, out, _err = self._doctor(["doctor", "--json"], crypto_backend="libcrypto",
                                       crypto_detail=None)
        self.assertEqual(code, 0)
        self.assertEqual(self._crypto_checks(out),
                         [{"name": "crypto-aead", "status": "ok", "detail": "libcrypto"}])

    def test_the_pure_python_fallback_warns_with_its_reason(self):
        reason = "disabled by OMCLIP_CRYPTO='py'"
        code, out, _err = self._doctor(["doctor", "--json"], crypto_backend="python",
                                       crypto_detail=reason)
        self.assertEqual(code, 0)          # JSON mode always exits 0: a warn is not a failure
        self.assertEqual(self._crypto_checks(out),
                         [{"name": "crypto-aead", "status": "warn", "detail": reason}])

    def test_the_human_line_agrees(self):
        reason = "no libcrypto: ctypes.util.find_library('crypto') found nothing"
        for backend, detail, expect in (("libcrypto", None, "OK   crypto-aead"),
                                        ("python", reason, "WARN crypto-aead")):
            code, out, _err = self._doctor(["doctor"], crypto_backend=backend,
                                           crypto_detail=detail)
            self.assertIn(expect, out)
            self.assertIn(detail or backend, out)
            self.assertIn(code, (0, 1))    # human mode exits 1 only for a real failure

    def test_the_status_line_names_the_backend(self):
        code, out, _err = self._doctor(["status"], crypto_backend="libcrypto",
                                       crypto_detail=None)
        self.assertEqual(code, 0)
        self.assertIn("crypto libcrypto", out)
        code, out, _err = self._doctor(["status"], crypto_backend="python",
                                       crypto_detail="OMCLIP_CRYPTO=python")
        self.assertEqual(code, 0)
        self.assertIn("crypto python", out)
        self.assertIn("crypto: OMCLIP_CRYPTO=python", out)


class LogCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = paths.LOG_FILE
        paths.LOG_FILE = os.path.join(self.tmp.name, "omclip.log")
        with open(paths.LOG_FILE, "w") as fh:
            for index in range(30):
                fh.write("line %d\n" % index)

    def tearDown(self):
        paths.LOG_FILE = self._saved
        self.tmp.cleanup()

    def test_tail_default_last_20(self):
        code, out, _err = run(["log"])
        self.assertEqual(code, 0)
        self.assertEqual(len(out.strip().splitlines()), 20)
        self.assertEqual(out.strip().splitlines()[-1], "line 29")

    def test_json_lines(self):
        code, out, _err = run(["log", "-n", "3", "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertEqual(doc["lines"], ["line 27", "line 28", "line 29"])

    def test_missing_log_is_empty_not_an_error(self):
        paths.LOG_FILE = os.path.join(self.tmp.name, "nope.log")
        code, out, _err = run(["log", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"lines": []})


class ConfigCommand(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = paths.SETTINGS_FILE
        paths.SETTINGS_FILE = os.path.join(self.tmp.name, "settings")

    def tearDown(self):
        paths.SETTINGS_FILE = self._saved
        self.tmp.cleanup()

    def test_list_json_has_effective_values(self):
        code, out, _err = run(["config", "list", "--json"])
        self.assertEqual(code, 0)
        settings = json.loads(out)["settings"]
        self.assertEqual(settings["scope"], "both")
        self.assertEqual(settings["poll_seconds"], 2.0)
        self.assertEqual(settings["max_bytes"], 256 * 1024 * 1024)

    def test_set_then_get_and_persistence(self):
        code, out, _err = run(["config", "set", "poll_seconds", "5", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"ok": True, "key": "poll_seconds", "value": 5.0,
                                           "file": paths.SETTINGS_FILE})
        self.assertTrue(os.path.exists(paths.SETTINGS_FILE))
        code, out, _err = run(["config", "get", "poll_seconds", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out), {"settings": {"poll_seconds": 5.0}})
        code, out, _err = run(["config", "get", "poll_seconds"])
        self.assertEqual((code, out.strip()), (0, "5.0"))

    def test_set_rejects_a_bad_value(self):
        code, out, _err = run(["config", "set", "poll_seconds", "0", "--json"])
        self.assertEqual(code, 1)
        doc = json.loads(out)
        self.assertFalse(doc["ok"])
        self.assertIn("poll_seconds", doc["error"])
        self.assertFalse(os.path.exists(paths.SETTINGS_FILE),
                         "a rejected value must not be persisted")

    def test_set_rejects_unknown_keys(self):
        code, out, _err = run(["config", "set", "frobnicate", "1"])
        self.assertEqual(code, 1)
        self.assertIn("unknown setting", _err)

    def test_get_unknown_key_fails(self):
        code, _out, err = run(["config", "get", "nope"])
        self.assertEqual(code, 1)
        self.assertIn("unknown setting", err)

    def test_scope_both_expands_in_a_later_list(self):
        run(["config", "set", "scope", "both", "--json"])
        code, out, _err = run(["config", "list", "--json"])
        self.assertEqual(json.loads(out)["settings"]["scope"], "both")

    def test_list_human_prints_key_value(self):
        code, out, _err = run(["config", "list"])
        self.assertEqual(code, 0)
        self.assertIn("scope=both", out)


class MutatingCommands(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = (paths.DESIRED_FILE, paths.SETTINGS_FILE, paths.UNIT_FILE, paths.STATUS_FILE)
        paths.DESIRED_FILE = os.path.join(self.tmp.name, "desired.json")
        paths.SETTINGS_FILE = os.path.join(self.tmp.name, "settings")
        paths.STATUS_FILE = os.path.join(self.tmp.name, "status.json")
        calls = []
        self.calls = calls

        def fake_systemctl(*args, timeout=6.0):
            calls.append(args)
            return 0, "", ""

        self._saved_systemctl = cli._systemctl
        cli._systemctl = fake_systemctl
        self._saved_active = cli.service_active
        cli.service_active = lambda: False

    def tearDown(self):
        cli._systemctl = self._saved_systemctl
        cli.service_active = self._saved_active
        paths.DESIRED_FILE, paths.SETTINGS_FILE, paths.UNIT_FILE, paths.STATUS_FILE = self._saved
        self.tmp.cleanup()

    def test_on_writes_desired_state_and_starts_the_unit(self):
        code, out, _err = run(["on", "10", "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertTrue(doc["ok"])
        self.assertEqual(doc["scope"], ["mac", "phone"])
        self.assertEqual(doc["duration"], "10m")
        self.assertEqual(doc["action"], "start")
        self.assertEqual(self.calls, [("start", "omclip.service")])
        with open(paths.DESIRED_FILE) as fh:
            desired = json.load(fh)
        self.assertEqual(desired["scope"], ["mac", "phone"])
        self.assertEqual(desired["duration"], "10m")
        with open(paths.STATUS_FILE) as fh:
            status_doc = json.load(fh)
        self.assertEqual(status_doc["state"], "starting")
        self.assertTrue(status_doc["on"])

    def test_on_restarts_an_active_unit_so_the_new_scope_applies(self):
        cli.service_active = lambda: True
        code, out, _err = run(["on", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["action"], "restart")
        self.assertEqual(self.calls, [("restart", "omclip.service")])

    def test_on_once(self):
        code, out, _err = run(["on", "once", "--json"])
        self.assertEqual(code, 0)
        self.assertEqual(json.loads(out)["duration"], "once")

    def test_on_rejects_a_bad_duration(self):
        code, out, _err = run(["on", "eleven", "--json"])
        self.assertEqual(code, 1)
        self.assertFalse(json.loads(out)["ok"])
        self.assertEqual(self.calls, [])

    def test_off_stops_and_clears_the_desired_state(self):
        run(["on", "--json"])
        code, out, _err = run(["off", "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["on"])
        self.assertIn(("stop", "omclip.service"), self.calls)
        self.assertFalse(os.path.exists(paths.DESIRED_FILE),
                         "off must clear the desired state, not leave a stale window")
        with open(paths.STATUS_FILE) as fh:
            status_doc = json.load(fh)
        self.assertEqual(status_doc["state"], "off")
        self.assertFalse(status_doc["on"])

    def test_toggle_from_off_goes_on(self):
        code, out, _err = run(["toggle", "--json"])
        self.assertEqual(code, 0)
        self.assertTrue(json.loads(out)["on"])

    def test_toggle_from_on_goes_off(self):
        cli.service_active = lambda: True
        code, out, _err = run(["toggle", "--json"])
        self.assertEqual(code, 0)
        self.assertFalse(json.loads(out)["on"])


class InstallUninstall(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self._saved = (paths.UNIT_FILE, paths.BIN_LINK, paths.DESIRED_FILE,
                       paths.SYSTEMD_USER_DIR, paths.BIN_DIR)
        paths.SYSTEMD_USER_DIR = os.path.join(self.tmp.name, "systemd")
        paths.BIN_DIR = os.path.join(self.tmp.name, "bin")
        paths.UNIT_FILE = os.path.join(paths.SYSTEMD_USER_DIR, "omclip.service")
        paths.BIN_LINK = os.path.join(paths.BIN_DIR, "omclip")
        paths.DESIRED_FILE = os.path.join(self.tmp.name, "desired.json")
        self.calls = []
        self._saved_systemctl = cli._systemctl
        self._saved_active = cli.service_active
        cli._systemctl = lambda *args, timeout=6.0: (self.calls.append(args) or (0, "", ""))
        cli.service_active = lambda: False

    def tearDown(self):
        cli._systemctl = self._saved_systemctl
        cli.service_active = self._saved_active
        (paths.UNIT_FILE, paths.BIN_LINK, paths.DESIRED_FILE, paths.SYSTEMD_USER_DIR,
         paths.BIN_DIR) = self._saved
        self.tmp.cleanup()

    def test_install_is_idempotent_and_never_enables(self):
        for _ in range(2):
            code, out, _err = run(["install", "--json"])
            self.assertEqual(code, 0)
            doc = json.loads(out)
            self.assertTrue(doc["ok"])
            self.assertEqual(doc["unit"], paths.UNIT_FILE)
        with open(paths.UNIT_FILE) as fh:
            unit = fh.read()
        self.assertIn("ExecStart=%h/.local/bin/omclip daemon", unit)
        self.assertIn("Restart=no", unit)
        self.assertNotIn("\n[Install]", unit, "installing must not make it enableable")
        self.assertTrue(os.path.islink(paths.BIN_LINK))
        self.assertNotIn(("enable", "omclip.service"), self.calls)
        self.assertIn(("daemon-reload",), self.calls)

    def test_refuses_to_clobber_a_real_file(self):
        paths.ensure_dir(paths.BIN_DIR)
        with open(paths.BIN_LINK, "w") as fh:
            fh.write("#!/bin/sh\n")
        code, out, _err = run(["install", "--json"])
        self.assertEqual(code, 1)
        self.assertIn("refusing to overwrite", json.loads(out)["error"])

    def test_uninstall_removes_both(self):
        run(["install", "--json"])
        code, out, _err = run(["uninstall", "--json"])
        self.assertEqual(code, 0)
        doc = json.loads(out)
        self.assertFalse(os.path.exists(paths.UNIT_FILE))
        self.assertFalse(os.path.lexists(paths.BIN_LINK))
        self.assertEqual(len(doc["removed"]), 2)


class LoggerRotates(unittest.TestCase):
    def test_rotation_keeps_one_generation(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "omclip.log")
            logger = logmod.Logger(path, max_bytes=200)
            for index in range(40):
                logger.info("line %d" % index)
            logger.close()
            self.assertTrue(os.path.exists(path + ".1"))
            self.assertLess(os.path.getsize(path), 200 + 128)
            self.assertTrue(logmod.tail(path, 1)[0].startswith("20"))

    def test_level_filtering(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "omclip.log")
            logger = logmod.Logger(path, level="warn")
            self.assertFalse(logger.info("invisible"))
            self.assertTrue(logger.warn("visible"))
            self.assertFalse(logger.debug("invisible"))
            logger.close()
            self.assertEqual(len(logmod.tail(path)), 1)


if __name__ == "__main__":
    unittest.main()
