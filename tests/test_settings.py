"""Settings parse/validate/reject: a bad value must never crash the daemon."""

import os
import subprocess
import sys
import tempfile
import unittest

import _support  # noqa: F401
from omclip import paths, settings


class DownloadDir(unittest.TestCase):
    """Where a fetched file lands: `~/Downloads` (omdrop's own destination), settable."""

    def _child(self, code):
        return subprocess.run([sys.executable, "-c", code], cwd=_support.ROOT,
                              capture_output=True, text=True, timeout=60)

    def test_the_default_is_downloads(self):
        # A child interpreter *without* `import _support`: that module repoints the default
        # at its own scratch directory for the rest of the suite, and `DEFAULTS` is read
        # once, at import.
        proc = self._child("import sys; sys.path.insert(0, 'lib');"
                           "from omclip import paths, settings;"
                           "print(settings.DEFAULTS['download_dir']);"
                           "print(paths.DEFAULT_DOWNLOAD_DIR);"
                           "print(settings.Settings({})['download_dir'])")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.splitlines(),
                         [os.path.join(paths.HOME, "Downloads")] * 3)

    def test_a_custom_absolute_dir_is_kept_and_tilde_expanded(self):
        ok, value, error = settings.validate("download_dir", "/srv/omclip-inbox")
        self.assertTrue(ok, error)
        self.assertEqual(value, "/srv/omclip-inbox")
        ok, value, error = settings.validate("download_dir", "~/Pictures/omclip")
        self.assertTrue(ok, error)
        self.assertEqual(value, os.path.join(paths.HOME, "Pictures", "omclip"))

    def test_a_relative_or_empty_dir_is_rejected(self):
        # The daemon's cwd is `/` under the unit: a relative path would write the file
        # somewhere nobody looks, so it is refused rather than resolved.
        for bad in ("Downloads", "sub/dir", "./here", "", "   "):
            ok, value, error = settings.validate("download_dir", bad)
            self.assertFalse(ok, "%r must be rejected" % bad)
            self.assertIsNone(value)
            self.assertTrue(error)

    def test_a_bad_value_falls_back_to_the_default_with_a_warning(self):
        values, warnings = settings.parse_text("download_dir=relative/path\n")
        self.assertEqual(values["download_dir"], settings.DEFAULTS["download_dir"])
        self.assertTrue(any("download_dir" in warning for warning in warnings), warnings)


class Defaults(unittest.TestCase):
    def test_effective_defaults(self):
        values, warnings = settings.parse_text("")
        self.assertEqual(warnings, [])
        self.assertEqual(values["scope"], "both")
        self.assertEqual(values["duration"], "forever")
        self.assertEqual(values["mac_host"], "localhost")
        self.assertEqual(values["mac_port"], 49152)
        self.assertEqual(values["poll_seconds"], 2.0)
        self.assertEqual(values["idle_poll_seconds"], 20.0)
        self.assertEqual(values["locked_poll_seconds"], 30.0)
        self.assertEqual(values["max_bytes"], 256 * 1024 * 1024)
        self.assertIs(values["ble_trigger"], True)
        self.assertIs(values["preview"], True)
        self.assertIs(values["notify"], False)
        self.assertEqual(values["log_level"], "info")
        self.assertEqual(values["phone_address"], "")

    def test_scope_list(self):
        self.assertEqual(settings.scope_list("mac"), ["mac"])
        self.assertEqual(settings.scope_list("phone"), ["phone"])
        self.assertEqual(settings.scope_list("both"), ["mac", "phone"])


class Parse(unittest.TestCase):
    def test_simple_pairs(self):
        values, warnings = settings.parse_text(
            "# comment\n\nscope=both\nmac_host=10.0.0.5\nmac_port=5000\npoll_seconds=0.5\n"
            "max_bytes=1024\nble_trigger=no\npreview=false\nnotify=yes\nlog_level=debug\n")
        self.assertEqual(warnings, [])
        self.assertEqual(values["scope"], "both")
        self.assertEqual(values["mac_host"], "10.0.0.5")
        self.assertEqual(values["mac_port"], 5000)
        self.assertEqual(values["poll_seconds"], 0.5)
        self.assertEqual(values["max_bytes"], 1024)
        self.assertIs(values["ble_trigger"], False)
        self.assertIs(values["preview"], False)
        self.assertIs(values["notify"], True)
        self.assertEqual(values["log_level"], "debug")

    def test_bad_values_fall_back_and_are_reported(self):
        values, warnings = settings.parse_text(
            "scope=ios\nmac_port=99999\npoll_seconds=abc\nmax_bytes=-1\nlog_level=loud\n"
            "ble_trigger=maybe\n")
        self.assertEqual(values["scope"], settings.DEFAULTS["scope"])
        self.assertEqual(values["mac_port"], settings.DEFAULTS["mac_port"])
        self.assertEqual(values["poll_seconds"], settings.DEFAULTS["poll_seconds"])
        self.assertEqual(values["max_bytes"], settings.DEFAULTS["max_bytes"])
        self.assertEqual(values["log_level"], settings.DEFAULTS["log_level"])
        self.assertEqual(values["ble_trigger"], settings.DEFAULTS["ble_trigger"])
        self.assertEqual(len(warnings), 6)
        self.assertTrue(all("using default" in w for w in warnings))

    def test_unknown_keys_are_ignored_with_a_warning(self):
        values, warnings = settings.parse_text("frobnicate=1\nscope=phone\n")
        self.assertNotIn("frobnicate", values)
        self.assertEqual(values["scope"], "phone")
        self.assertEqual(len(warnings), 1)
        self.assertIn("unknown setting", warnings[0])

    def test_lines_without_equals_are_reported(self):
        values, warnings = settings.parse_text("garbage\n")
        self.assertEqual(values, dict(settings.DEFAULTS))
        self.assertEqual(len(warnings), 1)

    def test_duration_uses_the_seconds_dialect(self):
        values, _warnings = settings.parse_text("duration=600\n")
        self.assertEqual(values["duration"], "10m")
        values, _warnings = settings.parse_text("duration=30\n")
        self.assertEqual(values["duration"], "30s")

    def test_whitespace_is_tolerated(self):
        values, warnings = settings.parse_text("  scope = both  \n")
        self.assertEqual(values["scope"], "both")
        self.assertEqual(warnings, [])


class Validate(unittest.TestCase):
    def test_accepts_and_coerces(self):
        self.assertEqual(settings.validate("mac_port", "8080"), (True, 8080, None))
        self.assertEqual(settings.validate("ble_trigger", "YES"), (True, True, None))
        self.assertEqual(settings.validate("max_bytes", "2048"), (True, 2048, None))
        ok, value, error = settings.validate("mac_host", "macbook.local")
        self.assertTrue(ok)
        self.assertEqual(value, "macbook.local")

    def test_rejects(self):
        for key, value in (("scope", "ios"), ("mac_port", "0"), ("mac_port", "70000"),
                           ("poll_seconds", "0.1"), ("idle_poll_seconds", "0"),
                           ("max_bytes", "10"), ("log_level", "verbose"),
                           ("ble_trigger", "maybe"), ("mac_host", ""),
                           ("duration", "once"), ("identity_dir", "")):
            ok, coercion, error = settings.validate(key, value)
            self.assertFalse(ok, "%s=%r should be rejected" % (key, value))
            self.assertIsNone(coercion)
            self.assertTrue(error)

    def test_unknown_key(self):
        ok, _value, error = settings.validate("nope", "1")
        self.assertFalse(ok)
        self.assertIn("unknown setting", error)


class Files(unittest.TestCase):
    def test_roundtrip_and_atomic_write(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "settings")
            values, _warnings = settings.parse_text("scope=both\npoll_seconds=5\n")
            settings.write(values, path)
            loaded, warnings = settings.load(path)
            self.assertEqual(warnings, [])
            self.assertEqual(loaded["scope"], "both")
            self.assertEqual(loaded["poll_seconds"], 5.0)
            self.assertEqual(os.listdir(tmp), ["settings"], "no temp file left behind")

    def test_missing_file_is_defaults(self):
        with tempfile.TemporaryDirectory() as tmp:
            loaded, warnings = settings.load(os.path.join(tmp, "nope"))
            self.assertEqual(loaded, dict(settings.DEFAULTS))
            self.assertEqual(warnings, [])

    def test_settings_object_folds_in_defaults(self):
        obj = settings.Settings({"scope": "both"})
        self.assertEqual(obj["mac_port"], settings.DEFAULTS["mac_port"])
        self.assertEqual(obj.scopes(), ["mac", "phone"])
        self.assertEqual(set(obj.as_dict()), set(settings.DEFAULTS))


if __name__ == "__main__":
    unittest.main()
