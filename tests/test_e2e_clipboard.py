"""End-to-end mirroring with the **real** Wayland clipboard.

The Apple peer is a loopback fake (no Apple device is required, and none is touched),
but everything on our side is real: Pair-Verify, `_systemInfo`, the payload request,
archive decoding, the decision, `wl-copy`, and `wl-paste` reads for echo suppression.

Skipped when there is no Wayland clipboard, and skipped when the current selection has
non-text types — the test restores the clipboard, and it refuses to destroy something it
cannot restore. The live Mac check is in `journal/2026-10-13-omclip-core.md`.
"""

import subprocess
import threading
import time
import unittest

import _support
from omclip import clipboard as clipmod
from omclip import daemon as daemonmod
from omclip import duration as durationmod
from omclip import identity as identitymod
from omclip import settings as settingsmod
from omclip import status
from test_session import FakePeer

TEXT = "omclip e2e mirror probe"
ARCHIVE = _support.inline_text(TEXT)


class Recorder:
    def __init__(self):
        self.lines = []

    def _add(self, level, message, **fields):
        self.lines.append((level, message, fields))
        return True

    error = lambda self, m, **f: self._add("error", m, **f)      # noqa: E731
    warn = lambda self, m, **f: self._add("warn", m, **f)        # noqa: E731
    info = lambda self, m, **f: self._add("info", m, **f)        # noqa: E731
    debug = lambda self, m, **f: self._add("debug", m, **f)      # noqa: E731


#: Types a text/plain selection legitimately carries (X11 atoms and wl-clipboard's own
#: meta-types). Anything else means restoring would lose data the test cannot put back.
TEXTY = ("STRING", "UTF8_STRING", "TEXT", "COMPOUND_TEXT", "TARGETS", "MULTIPLE",
         "SAVE_TARGETS", "DELETE", "TIMESTAMP")


def texty(mime):
    return mime.startswith("text/") or mime in TEXTY


def wayland():
    return bool(clipmod.wayland_available() and clipmod.tool("wl-copy")
                and clipmod.tool("wl-paste"))


def paste(*args):
    """(types, text-or-None) of one selection: the clipboard, or PRIMARY with --primary."""
    binary = clipmod.tool("wl-paste")
    proc = subprocess.run([binary, "--list-types"] + list(args), capture_output=True,
                          check=False)
    types = [t for t in proc.stdout.decode().split() if t] if proc.returncode == 0 else []
    text = None
    if any(t.startswith("text/") or t in TEXTY for t in types):
        proc = subprocess.run([binary, "--no-newline", "--type", "text/plain"] + list(args),
                              capture_output=True, check=False)
        if proc.returncode == 0:
            text = proc.stdout
    return types, text


def snapshot():
    """(clipboard, primary) as paste() tuples — this test must put both back."""
    return paste(), paste("--primary")


def restore(saved):
    binary = clipmod.tool("wl-copy")
    if not binary:
        return
    for extra, (types, text) in (([], saved[0]), (["--primary"], saved[1])):
        if text is not None:
            subprocess.run([binary, "--type", "text/plain"] + extra, input=text, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        elif not types:
            subprocess.run([binary, "--clear"] + extra, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


@unittest.skipUnless(wayland(), "needs a Wayland clipboard (wl-copy/wl-paste)")
class MirrorEndToEnd(unittest.TestCase):
    def setUp(self):
        self.saved = snapshot()
        unsupported = [t for types, _text in self.saved for t in types if not texty(t)]
        if unsupported:
            restore(self.saved)
            self.skipTest("refusing to clobber a selection this test cannot restore (%s)"
                          % ", ".join(sorted(set(unsupported))))

    def tearDown(self):
        restore(self.saved)

    def _daemon(self, peer):
        values = {"scope": "mac", "poll_seconds": 2.0, "max_bytes": 8 * 1024 * 1024,
                  "mac_host": "127.0.0.1", "mac_port": peer.port}
        log = Recorder()
        daemon = daemonmod.Daemon(settingsmod.Settings(values), log=log)
        daemon.window = durationmod.Window("forever", None)
        daemon.stop_event = threading.Event()   # run() normally does this
        daemon.identity = identitymod.Identity(bytes(range(32)), bytes(32), "IDS-E2E")
        daemon.first_round_done = True
        daemon._health = {"bluetooth": "off", "bluetooth_detail": None, "awdl": "down",
                          "omdrop": "off", "omdrop_owned": False, "wl_clipboard": True,
                          "wayland": True, "ble_backend": "unavailable", "ble_detail": None}
        daemon.last_health = time.monotonic()
        daemon._creds = []
        daemon.last_creds = time.monotonic()
        # No mDNS lookup: this test talks to the loopback peer, not to the LAN.
        daemon._mac_mdns_at = time.monotonic()
        return daemon, log

    def test_inline_item_lands_on_the_clipboard_and_a_repeat_does_not(self):
        peer = FakePeer(respond=lambda obj: {"rAdvPayload": b"\x00",
                                             "rActPayload": ARCHIVE})
        peer.start()
        daemon, log = self._daemon(peer)
        try:
            subprocess.run([clipmod.tool("wl-copy"), "--clear"], check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            mac = daemon.by_key["mac"]
            daemon._poll_peer(mac)
            self.assertEqual(mac.state, "idle")
            self.assertEqual(daemon.mirrored_total, 1)
            self.assertEqual(mac.last_generation["reason"], "mirror")
            self.assertTrue(mac.last_generation["mirrored"])
            read = clipmod.Clipboard().read_local("text/plain")
            self.assertIsNotNone(read, "nothing on the clipboard after mirroring")
            self.assertEqual(read[1].decode(), TEXT)
            # Applications ask for UTF8_STRING / text/plain;charset=utf-8 far more often
            # than for the bare text/plain we pass to wl-copy, and a text offer must
            # advertise them (wl-copy adds the standard targets for a text type).
            types, _ = paste()
            for target in ("text/plain", "text/plain;charset=utf-8", "TEXT", "STRING",
                           "UTF8_STRING"):
                self.assertIn(target, types, "text offer is missing %s" % target)
            # PRIMARY is what `SHIFT + Insert` pastes in a terminal window, and universal
            # paste sends exactly that there.
            _primary_types, primary = paste("--primary")
            self.assertIsNotNone(primary, "nothing on the PRIMARY selection after mirroring")
            self.assertEqual(primary.decode(), TEXT)
            self.assertEqual(daemon.last_preview, TEXT)
            self.assertTrue(status.validate(daemon.status_doc()) == [])

            # The user (or anything else) replaces the selection; the peer has no new
            # generation, so the daemon must leave that replacement alone.
            sentinel = b"omclip sentinel: do not clobber"
            subprocess.run([clipmod.tool("wl-copy")], input=sentinel, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            daemon._poll_peer(mac)
            self.assertEqual(daemon.mirrored_total, 1, "same generation must not re-mirror")
            self.assertEqual(daemon.counters["unchanged"], 1)
            after = clipmod.Clipboard().read_local("text/plain")
            self.assertEqual(after[1], sentinel, "the clipboard was clobbered by a repeat")

            # And a session that fetches the same generation again is still one session.
            self.assertIs(daemon.by_key["mac"].session, mac.session)
            self.assertGreaterEqual(len(peer.requests), 3)
        finally:
            daemon.by_key["mac"].close_session()
            peer.listener.close()


if __name__ == "__main__":
    unittest.main()
