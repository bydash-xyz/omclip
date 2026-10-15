"""omdrop status interpretation: when is an AWDL window really open."""

import unittest

import _support  # noqa: F401 - path setup + hermetic radio
from omclip import omdrop

#: Measured 2026-10-13 after a suspend: receiver up on the monotonic user timer, radio
#: half torn down by its wall-clock supervisor.
COLLAPSED = {"receiving": True, "visible": False, "remaining": 262, "mode": "timed",
             "reason": "expired", "rx_proven": True}


class WindowActive(unittest.TestCase):
    def test_live_windows(self):
        self.assertTrue(omdrop.window_active({"receiving": True, "visible": True,
                                              "mode": "forever", "reason": "ok"}))
        self.assertTrue(omdrop.window_active({"mode": "timed", "remaining": 300}))

    def test_closed_windows(self):
        self.assertFalse(omdrop.window_active({"receiving": False, "mode": "off"}))
        self.assertFalse(omdrop.window_active({"mode": "timed", "remaining": 0}))
        self.assertFalse(omdrop.window_active({"receiving": False, "mode": "timed",
                                               "remaining": 30}))
        self.assertIsNone(omdrop.window_active(None))

    def test_collapsed_radio_is_not_an_open_window(self):
        self.assertTrue(omdrop.radio_collapsed(COLLAPSED))
        self.assertFalse(omdrop.window_active(COLLAPSED))
        for reason in ("stopped", "no_awdl0"):
            self.assertTrue(omdrop.radio_collapsed(dict(COLLAPSED, reason=reason)))

    def test_not_collapsed(self):
        # Radio half not installed (`visible: null`) or still live: no verdict against it.
        self.assertFalse(omdrop.radio_collapsed(dict(COLLAPSED, visible=None)))
        self.assertFalse(omdrop.radio_collapsed(dict(COLLAPSED, reason="ok")))
        self.assertFalse(omdrop.radio_collapsed(dict(COLLAPSED, reason="unproven")))
        self.assertFalse(omdrop.radio_collapsed(dict(COLLAPSED, receiving=False)))
        self.assertFalse(omdrop.radio_collapsed(None))


class StartStop(unittest.TestCase):
    def setUp(self):
        self.args = []
        self._saved = omdrop._run
        omdrop._run = lambda args, timeout=None: self.args.append(args) or (0, "ok\n", "")

    def tearDown(self):
        omdrop._run = self._saved

    def test_stop_force_flag(self):
        omdrop.stop()
        omdrop.stop(force=True)
        self.assertEqual(self.args, [["off"], ["off", "--force"]])


if __name__ == "__main__":
    unittest.main()
