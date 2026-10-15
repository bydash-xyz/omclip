"""Duration parsing: the CLI dialect (bare = minutes) and the settings dialect.

The two dialects differ on purpose (`on 10` is 10 minutes, `duration=10` is 10 seconds),
so both are pinned here.
"""

import unittest

import _support  # noqa: F401
from omclip import duration


class CliDialect(unittest.TestCase):
    def test_bare_integer_is_minutes(self):
        self.assertEqual(duration.parse_duration("10"), ("10m", 600, False))
        self.assertEqual(duration.parse_duration("1"), ("1m", 60, False))
        self.assertEqual(duration.parse_duration("90"), ("90m", 5400, False))

    def test_units(self):
        self.assertEqual(duration.parse_duration("30s"), ("30s", 30, False))
        self.assertEqual(duration.parse_duration("10m"), ("10m", 600, False))
        self.assertEqual(duration.parse_duration("1h"), ("1h", 3600, False))
        self.assertEqual(duration.parse_duration("2h"), ("2h", 7200, False))

    def test_compound(self):
        self.assertEqual(duration.parse_duration("1h30m"), ("1h30m", 5400, False))

    def test_forever_is_the_default(self):
        self.assertEqual(duration.parse_duration(""), ("forever", None, False))
        self.assertEqual(duration.parse_duration(None), ("forever", None, False))
        self.assertEqual(duration.parse_duration("forever"), ("forever", None, False))

    def test_once(self):
        self.assertEqual(duration.parse_duration("once"), ("once", None, True))

    def test_case_and_space_insensitive(self):
        self.assertEqual(duration.parse_duration(" 10M "), ("10m", 600, False))
        self.assertEqual(duration.parse_duration("FOREVER"), ("forever", None, False))

    def test_rejects_junk(self):
        for bad in ("ten", "10x", "-5", "1.5h", "5 minutes", "0s"):
            with self.assertRaises(ValueError, msg=bad):
                duration.parse_duration(bad)

    def test_once_can_be_refused(self):
        with self.assertRaises(ValueError):
            duration.parse_duration("once", allow_once=False)


class SettingsDialect(unittest.TestCase):
    def test_bare_integer_is_seconds(self):
        self.assertEqual(duration.parse_settings_duration("10"), ("10s", 10))
        self.assertEqual(duration.parse_settings_duration("600"), ("10m", 600))

    def test_units_and_forever(self):
        self.assertEqual(duration.parse_settings_duration("30m"), ("30m", 1800))
        self.assertEqual(duration.parse_settings_duration("forever"), ("forever", None))
        self.assertEqual(duration.parse_settings_duration(""), ("forever", None))

    def test_once_is_not_a_settings_duration(self):
        with self.assertRaises(ValueError):
            duration.parse_settings_duration("once")

    def test_zero_is_rejected(self):
        with self.assertRaises(ValueError):
            duration.parse_settings_duration("0")


class Formatting(unittest.TestCase):
    def test_canon(self):
        self.assertEqual(duration.canon(3600), "1h")
        self.assertEqual(duration.canon(600), "10m")
        self.assertEqual(duration.canon(30), "30s")
        self.assertEqual(duration.canon(5400), "90m")
        self.assertEqual(duration.canon(None), "forever")

    def test_format_seconds(self):
        self.assertEqual(duration.format_seconds(None), "forever")
        self.assertEqual(duration.format_seconds(45), "45s")
        self.assertEqual(duration.format_seconds(600), "10m00s")
        self.assertEqual(duration.format_seconds(3720), "1h02m")


class WindowTests(unittest.TestCase):
    def test_forever_has_no_expiry(self):
        window = duration.Window("forever", None, started_at=1000)
        self.assertIsNone(window.expires_at)
        self.assertIsNone(window.seconds_left(now=1000))
        self.assertFalse(window.expired(now=10 ** 9))

    def test_timed_window(self):
        window = duration.Window("10m", 600, started_at=1000)
        self.assertEqual(window.expires_at, 1600)
        self.assertEqual(window.seconds_left(now=1300), 300)
        self.assertEqual(window.seconds_left(now=1600), 0)
        self.assertTrue(window.expired(now=1600))
        self.assertFalse(window.expired(now=1599))

    def test_seconds_left_never_negative(self):
        window = duration.Window("30s", 30, started_at=1000)
        self.assertEqual(window.seconds_left(now=5000), 0)

    def test_once_window_is_a_forever_window_that_stops_early(self):
        window = duration.Window("once", None, once=True, started_at=1000)
        self.assertIsNone(window.expires_at)
        self.assertTrue(window.once)


if __name__ == "__main__":
    unittest.main()
