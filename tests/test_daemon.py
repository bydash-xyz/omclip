"""Daemon logic without the network: cadence, states, mirroring, ownership, single instance."""

import os
import tempfile
import time
import unittest
import unittest.mock

import _support
from omclip import bulk as bulkmod
from omclip import crypto
from omclip import daemon as daemonmod
from omclip import duration as durationmod
from omclip import identity as identitymod
from omclip import pasteboard, paths, peer as peermod, settings as settingsmod, status

ARCHIVE = _support.inline_text("Braun : Designed to Keep")
DATA = b"Braun : Designed to Keep"


class Recorder:
    """Captures log calls instead of writing a file."""

    def __init__(self):
        self.lines = []

    def _add(self, level, message, **fields):
        self.lines.append((level, message, fields))
        return True

    error = lambda self, m, **f: self._add("error", m, **f)      # noqa: E731
    warn = lambda self, m, **f: self._add("warn", m, **f)        # noqa: E731
    info = lambda self, m, **f: self._add("info", m, **f)        # noqa: E731
    debug = lambda self, m, **f: self._add("debug", m, **f)      # noqa: E731

    def messages(self, level=None):
        return [m for lvl, m, _f in self.lines if level is None or lvl == level]


def unavailable_fetch(pb, **kwargs):
    """The companion-stream fetch for unit tests: it must never open a socket.

    A bulk generation whose payload cannot be fetched is a case the daemon has to report
    honestly, so it is also the natural default here — the tests that do fetch replace
    `daemon.bulk_fetch` themselves.
    """
    raise bulkmod.BulkError("no _continuity._tcp instance named 97b1f7346d19 on the LAN")


class FakeClipboard:
    def __init__(self, local=None):
        self.local = local
        self.copies = []
        self._written = []

    def read_local(self, mime=None):
        return self.local

    def copy(self, data, uti):
        self.copies.append((uti, bytes(data)))
        return "text/plain"

    def remember(self, digest):
        self._written.append(digest)

    def written(self):
        return list(self._written)


def make_daemon(**overrides):
    values = {"scope": "both", "poll_seconds": 2.0, "idle_poll_seconds": 20.0,
              "locked_poll_seconds": 30.0, "max_bytes": 8 * 1024 * 1024}
    values.update(overrides)
    log = Recorder()
    daemon = daemonmod.Daemon(settingsmod.Settings(values), log=log)
    daemon.window = durationmod.Window("forever", None)
    daemon.first_round_done = True
    daemon.clip = FakeClipboard()
    daemon.bulk_fetch = unavailable_fetch
    # A stand-in identity: unit tests never authenticate, but the daemon refuses to
    # report peer problems without one.
    daemon.identity = identitymod.Identity(b"\x01" * 32, b"\x02" * 32, "IDS-TEST")
    # Fixed health so status_doc() does not run live probes in unit tests.
    daemon._health = {"bluetooth": "off", "bluetooth_detail": "inactive", "awdl": "down",
                      "omdrop": "off", "omdrop_owned": False, "wl_clipboard": True,
                      "wayland": True, "ble_backend": "unavailable", "ble_detail": "no gi"}
    daemon._creds = []
    daemon.last_health = time.monotonic()
    daemon.last_creds = time.monotonic()   # no openssl spawn per unit test
    return daemon, log


class StatusDocument(unittest.TestCase):
    def test_status_doc_conforms_to_the_frozen_schema(self):
        daemon, _log = make_daemon()
        daemon.by_key["mac"].set_state("idle")
        doc = daemon.status_doc()
        self.assertEqual(status.validate(doc), [])
        self.assertEqual(doc["state"], "on")
        self.assertEqual(set(doc["clipboard"]["skipped"]), set(status.SKIP_REASONS))
        self.assertEqual(doc["instance"]["pid"], os.getpid())
        self.assertGreater(doc["instance"]["rss_kb"], 0)
        self.assertIsInstance(doc["heartbeat"], int)

    def test_status_doc_reports_the_live_crypto_backend(self):
        daemon, _log = make_daemon()
        doc = daemon.status_doc()
        self.assertEqual(doc["health"]["crypto_backend"], crypto.aead_backend())
        self.assertEqual(doc["health"]["crypto_detail"], crypto.aead_detail())
        # The file the daemon writes mirrors them at the top level, like ble_backend.
        self.assertEqual(doc["crypto_backend"], crypto.aead_backend())
        self.assertEqual(doc["crypto_detail"], crypto.aead_detail())

    def test_status_doc_follows_a_fallback_to_pure_python(self):
        # The daemon reads the backend at write time, so a call-time libcrypto failure is
        # visible in the next document instead of an unobservable speed regression.
        daemon, _log = make_daemon()
        reason = "disabled by OMCLIP_CRYPTO='py'"
        with unittest.mock.patch.object(crypto, "_libcrypto", None), \
                unittest.mock.patch.object(crypto, "_LIBCRYPTO_ERROR", reason):
            doc = daemon.status_doc()
        self.assertEqual(doc["health"]["crypto_backend"], "python")
        self.assertEqual(doc["health"]["crypto_detail"], reason)
        self.assertEqual(doc["crypto_backend"], "python")
        self.assertEqual(doc["crypto_detail"], reason)
        self.assertEqual(status.validate(doc), [])

    def test_scope_without_phone_leaves_it_disabled(self):
        daemon, _log = make_daemon(scope="mac")
        doc = daemon.status_doc()
        self.assertEqual(doc["scope"], ["mac"])
        self.assertEqual([p["key"] for p in doc["peers"]], ["mac", "phone"])
        self.assertEqual(daemon.by_key["phone"].state, "disabled")


class States(unittest.TestCase):
    def test_starting_on_degraded_error(self):
        daemon, _log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        peer.set_state("error")
        daemon.first_round_done = False
        self.assertEqual(daemon.current_state(), "starting")
        daemon.first_round_done = True
        self.assertEqual(daemon.current_state(), "degraded")
        peer.set_state("idle")
        self.assertEqual(daemon.current_state(), "on")
        peer.set_state("error")
        self.assertEqual(daemon.current_state(), "degraded")
        daemon.fatal.append("identity missing")
        self.assertEqual(daemon.current_state(), "error")

    def test_degraded_reasons_are_reported(self):
        daemon, _log = make_daemon(scope="mac")
        daemon.by_key["mac"].on_failure("connection refused")
        errors = daemon.error_list()
        self.assertEqual(len(errors), 1)
        self.assertIn("mac", errors[0])
        self.assertIn("connection refused", errors[0])

    def test_no_errors_when_healthy(self):
        daemon, _log = make_daemon(scope="mac")
        daemon.by_key["mac"].set_state("idle")
        self.assertEqual(daemon.error_list(), [])


class Cadence(unittest.TestCase):
    def test_fast_while_recently_active(self):
        daemon, _log = make_daemon()
        peer = daemon.by_key["mac"]
        peer.last_seen = int(time.time())
        self.assertEqual(daemon.cadence(peer), 2.0)

    def test_idle_when_nothing_has_moved_for_five_minutes(self):
        daemon, _log = make_daemon()
        peer = daemon.by_key["mac"]
        peer.last_seen = int(time.time()) - 301
        self.assertEqual(daemon.cadence(peer), 20.0)

    def test_locked_phone_uses_the_locked_cadence(self):
        daemon, _log = make_daemon()
        peer = daemon.by_key["phone"]
        peer.last_seen = int(time.time())
        peer.state = "locked"
        self.assertEqual(daemon.cadence(peer), 30.0)

    def test_ble_trigger_opens_a_fast_window(self):
        daemon, _log = make_daemon()
        peer = daemon.by_key["phone"]
        peer.last_seen = int(time.time()) - 900
        peer.force_fast_until = time.monotonic() + 60
        self.assertEqual(daemon.cadence(peer), 2.0)

    def test_schedule_keeps_a_backoff_deadline(self):
        daemon, _log = make_daemon()
        peer = daemon.by_key["mac"]
        peer.on_failure("boom")
        deadline = peer.next_attempt
        daemon._schedule(peer)
        self.assertEqual(peer.next_attempt, deadline, "backoff must not be overwritten")

    def test_schedule_without_backoff_uses_the_cadence(self):
        daemon, _log = make_daemon()
        peer = daemon.by_key["mac"]
        peer.last_seen = int(time.time())
        peer.next_attempt = 0.0
        daemon._schedule(peer)
        self.assertLessEqual(peer.next_attempt, time.monotonic() + 2.0)

    def test_a_successful_poll_arms_the_cadence_not_the_next_tick(self):
        # Regression: on_success() used to zero the deadline, so the loop polled the Mac
        # roughly once a second instead of every poll_seconds.
        daemon, _log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        peer.on_success()                               # a poll just succeeded
        peer.last_seen = int(time.time()) - 900         # nothing seen for 15 minutes
        peer.next_attempt = 0.0
        daemon._schedule(peer)
        self.assertGreaterEqual(peer.next_attempt - time.monotonic(),
                                daemon.settings["idle_poll_seconds"] - 0.5)
        peer.last_seen = int(time.time())              # active cadence
        peer.next_attempt = 0.0
        daemon._schedule(peer)
        self.assertGreaterEqual(peer.next_attempt - time.monotonic(),
                                daemon.settings["poll_seconds"] - 0.5)


class BleTrigger(unittest.TestCase):
    def test_clipboard_beacon_forces_a_poll(self):
        daemon, _log = make_daemon()
        for peer in daemon.peers:
            if peer.in_scope:
                peer.last_seen = int(time.time()) - 9000
                peer.next_attempt = time.monotonic() + 60
        daemon._wake_w = None                        # no socketpair in unit tests
        daemon.on_ble("5f:cb:2b:66:19:72", 0x08, 0x37FF, b"\x08\xff\x37")
        for peer in daemon.peers:
            if peer.in_scope:
                self.assertEqual(peer.next_attempt, 0.0)
                self.assertGreater(peer.force_fast_until, time.monotonic())

    def test_status_without_the_clipboard_bit_is_ignored(self):
        daemon, _log = make_daemon()
        daemon._wake_w = None
        daemon.on_ble("5f:cb:2b:66:19:72", 0x00, 0x3800, b"\x00\x00\x38")
        for peer in daemon.peers:
            self.assertEqual(peer.force_fast_until, 0.0)

    def test_triggers_are_rate_limited_to_two_seconds(self):
        daemon, _log = make_daemon()
        daemon._wake_w = None
        daemon.on_ble("aa:bb:cc:dd:ee:ff", 0x08, 1, b"\x08\x01\x00")
        first = daemon.by_key["mac"].force_fast_until
        daemon.on_ble("aa:bb:cc:dd:ee:ff", 0x08, 2, b"\x08\x02\x00")
        self.assertEqual(daemon.by_key["mac"].force_fast_until, first,
                         "a second beacon inside 2 s must not re-arm anything")
        daemon.last_ble_trigger -= 5.0                 # pretend 5 s passed
        daemon.on_ble("aa:bb:cc:dd:ee:ff", 0x08, 3, b"\x08\x03\x00")
        self.assertNotEqual(daemon.by_key["mac"].force_fast_until, first)
        self.assertEqual(daemon.by_key["mac"].force_fast_until, daemon.last_ble_trigger + 60.0)


class Mirroring(unittest.TestCase):
    def test_mirror_path(self):
        daemon, log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(ARCHIVE))
        self.assertEqual(daemon.clip.copies, [("public.utf8-plain-text", DATA)])
        self.assertEqual(daemon.mirrored_total, 1)
        self.assertEqual(daemon.last_digest, pasteboard.digest_of("public.utf8-plain-text", DATA))
        self.assertEqual(daemon.last_uti, "public.utf8-plain-text")
        self.assertEqual(daemon.last_bytes, len(DATA))
        self.assertIsNone(daemon.last_file, "a text mirror is not a file")
        self.assertEqual(daemon.last_preview, DATA.decode())
        self.assertEqual(peer.last_generation["reason"], "mirror")
        self.assertTrue(peer.last_generation["mirrored"])
        self.assertEqual(daemon.clip.written(), [daemon.last_digest])
        self.assertEqual(daemon.counters["unchanged"], 0)
        self.assertIn("mirrored", log.messages("info"))

    def test_second_identical_generation_is_unchanged(self):
        daemon, _log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        pb = pasteboard.parse_pasteboard_archive(ARCHIVE)
        daemon._handle_pasteboard(peer, pb)
        daemon._handle_pasteboard(peer, pb)
        self.assertEqual(len(daemon.clip.copies), 1)
        self.assertEqual(daemon.counters["unchanged"], 1)
        self.assertEqual(peer.last_generation["reason"], "unchanged")

    def test_bulk_generation_is_counted_and_not_mirrored(self):
        daemon, log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        archive = _support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 200000}}],
            extra=_support.bulk_descriptor(), data_size=200000, extra_type=1)
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(archive))
        self.assertEqual(daemon.clip.copies, [])
        self.assertEqual(daemon.counters["bulk"], 1)
        self.assertTrue(peer.last_generation["bulk"])
        self.assertEqual(peer.last_generation["bytes"], 200000)
        self.assertFalse(peer.last_generation["mirrored"])

    def test_bulk_log_line_is_written_once_per_generation(self):
        daemon, log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        archive = _support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 200000}}],
            extra=_support.bulk_descriptor(), data_size=200000)
        pb = pasteboard.parse_pasteboard_archive(archive)
        for _ in range(5):
            daemon._handle_pasteboard(peer, pb)
        # One attempt per generation, then `unchanged`: the descriptor repeats for as long
        # as the sender holds the copy, and re-attempting it every 2 s is what used to keep
        # `clipboard.skipped.bulk` climbing (732 for one generation, measured 2026-10-14).
        self.assertEqual(daemon.counters["bulk"], 1, "one attempt, not one per poll")
        self.assertEqual(daemon.counters["unchanged"], 4, "the repeats are `unchanged`")
        self.assertEqual(len([m for m in log.messages("info") if "bulk" in m]), 1,
                         "and the log says it once, not every 2 s")

    def test_local_echo_is_counted(self):
        daemon, _log = make_daemon(scope="mac")
        daemon.clip = FakeClipboard(local=("text/plain", DATA))
        peer = daemon.by_key["mac"]
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(ARCHIVE))
        self.assertEqual(daemon.clip.copies, [])
        self.assertEqual(daemon.counters["local_echo"], 1)

    def test_oversize_is_counted(self):
        daemon, _log = make_daemon(scope="mac", max_bytes=8)
        peer = daemon.by_key["mac"]
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(ARCHIVE))
        self.assertEqual(daemon.clip.copies, [])
        self.assertEqual(daemon.counters["oversize"], 1)

    def test_empty_and_nodata_are_counted(self):
        daemon, _log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(
            _support.pasteboard_archive(null_root=True)))
        daemon._handle_pasteboard(peer, None)
        self.assertEqual(daemon.counters["empty"], 1)
        self.assertEqual(daemon.counters["nodata"], 1)
        self.assertEqual(daemon.clip.copies, [])

    def test_once_window_stops_after_the_first_mirror(self):
        daemon, _log = make_daemon(scope="mac")
        daemon.window = durationmod.Window("once", None, once=True)
        peer = daemon.by_key["mac"]
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(ARCHIVE))
        self.assertEqual(daemon.stop_reason, "once")

    def test_preview_can_be_disabled(self):
        daemon, _log = make_daemon(scope="mac", preview=False)
        peer = daemon.by_key["mac"]
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(ARCHIVE))
        self.assertIsNone(daemon.last_preview)

    def test_preview_is_never_taken_for_non_text(self):
        daemon, _log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        png = _support.pasteboard_archive([{"public.png": {"offset": 0, "size": 4}}],
                                          extra=b"\x89PNG")
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(png))
        self.assertIsNone(daemon.last_preview)
        self.assertEqual(daemon.last_uti, "public.png")

    def test_failed_clipboard_write_does_not_claim_a_mirror(self):
        daemon, log = make_daemon(scope="mac")
        daemon.clip.copy = lambda data, uti: None
        peer = daemon.by_key["mac"]
        daemon._handle_pasteboard(peer, pasteboard.parse_pasteboard_archive(ARCHIVE))
        self.assertEqual(daemon.mirrored_total, 0)
        self.assertEqual(daemon.clip.written(), [])
        self.assertFalse(peer.last_generation["mirrored"],
                         "the status must not claim a mirror that failed")
        self.assertEqual(peer.last_error, "clipboard write failed")
        self.assertTrue(any("clipboard write failed" in message
                            for message in log.messages("error")))


class SingleInstance(unittest.TestCase):
    def test_second_daemon_refuses_the_lock(self):
        with tempfile.TemporaryDirectory() as tmp:
            saved_dir, saved_lock = paths.STATE_DIR, paths.LOCK_FILE
            paths.STATE_DIR = tmp
            paths.LOCK_FILE = os.path.join(tmp, "lock")
            try:
                first, _log = make_daemon(scope="mac")
                second, _log2 = make_daemon(scope="mac")
                self.assertTrue(first._acquire_lock())
                self.assertFalse(second._acquire_lock())
                os.close(first._lock_fd)
                first._lock_fd = None
                self.assertTrue(second._acquire_lock())
                os.close(second._lock_fd)
            finally:
                paths.STATE_DIR, paths.LOCK_FILE = saved_dir, saved_lock


class OwnedOmdropWindow(unittest.TestCase):
    def test_scope_without_phone_never_touches_omdrop(self):
        daemon, log = make_daemon(scope="mac")
        calls = []
        saved = daemonmod.omdrop.start
        daemonmod.omdrop.start = lambda *a, **k: calls.append(a) or (True, "ok")
        try:
            daemon._open_omdrop_window()
        finally:
            daemonmod.omdrop.start = saved
        self.assertEqual(calls, [])
        self.assertFalse(daemon.omdrop_owned)
        self.assertEqual(log.messages(), [])

    def test_phone_scope_starts_a_window_and_records_ownership(self):
        daemon, _log = make_daemon(scope="both")
        daemon.window = durationmod.Window("10m", 600)
        calls = []
        saved_status, saved_start = daemonmod.omdrop.status, daemonmod.omdrop.start
        daemonmod.omdrop.status = lambda: {"mode": "off", "remaining": None, "reason": "stopped"}
        daemonmod.omdrop.start = lambda duration=None, timeout=8.0, ensure_bluetooth=True: (
            calls.append(duration) or (True, "advertising"))
        try:
            daemon._open_omdrop_window()
        finally:
            daemonmod.omdrop.status, daemonmod.omdrop.start = saved_status, saved_start
        self.assertEqual(calls, ["10m"])
        self.assertTrue(daemon.omdrop_owned)
        self.assertEqual(daemon.omdrop_window, "10m")

    def test_an_existing_window_is_left_alone(self):
        daemon, _log = make_daemon(scope="both")
        calls = []
        saved_status, saved_start = daemonmod.omdrop.status, daemonmod.omdrop.start
        daemonmod.omdrop.status = lambda: {"mode": "on", "remaining": 300}
        daemonmod.omdrop.start = lambda *a, **k: calls.append(a) or (True, "ok")
        try:
            daemon._open_omdrop_window()
        finally:
            daemonmod.omdrop.status, daemonmod.omdrop.start = saved_status, saved_start
        self.assertEqual(calls, [])
        self.assertFalse(daemon.omdrop_owned, "a window we did not open is not ours to close")

    def test_failed_start_is_recorded_reported_and_not_spammed(self):
        from omclip import discovery
        daemon, log = make_daemon(scope="both")
        saved = (daemonmod.omdrop.status, daemonmod.omdrop.start, discovery.awdl_up)
        daemonmod.omdrop.status = lambda: {"mode": "off", "remaining": None}
        daemonmod.omdrop.start = lambda duration=None, timeout=8.0, ensure_bluetooth=True: (
            False, "pkexec must be setuid root")
        discovery.awdl_up = lambda iface="awdl0": False
        try:
            daemon._open_omdrop_window()
            daemon._open_omdrop_window()                 # same failure again
            self.assertFalse(daemon.omdrop_owned)
            self.assertEqual(daemon.omdrop_error, "pkexec must be setuid root")
            warnings = [m for m in log.messages("warn") if "omdrop window" in m]
            self.assertEqual(len(warnings), 1, "one line per distinct error")
            # ...and the phone peer says why, not just "awdl0 is down".
            found = daemon._resolve_phone(daemon.by_key["phone"])
            self.assertEqual(found.state, "unreachable")
            self.assertIn("pkexec must be setuid root", found.detail)
            self.assertIn("could not open an omdrop window", found.detail)
        finally:
            (daemonmod.omdrop.status, daemonmod.omdrop.start, discovery.awdl_up) = saved

    def test_window_is_retried_but_not_more_often_than_the_interval(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        calls = []
        saved = (daemonmod.omdrop.status, daemonmod.omdrop.start, discovery.awdl_up)
        daemonmod.omdrop.status = lambda: {"mode": "off", "remaining": None}
        daemonmod.omdrop.start = lambda duration=None, timeout=8.0, ensure_bluetooth=True: (calls.append(duration)
                                                                    or (True, "advertising"))
        discovery.awdl_up = lambda iface="awdl0": False
        try:
            daemon._tick_omdrop()                        # first retry: opens the window
            self.assertEqual(len(calls), 1)
            self.assertTrue(daemon.omdrop_owned)
            daemon.omdrop_owned = False                  # pretend it went away again
            daemon._tick_omdrop()                        # too soon
            self.assertEqual(len(calls), 1)
            daemon.omdrop_retry_at = 0.0                 # interval elapsed
            daemon._tick_omdrop()
            self.assertEqual(len(calls), 2)
        finally:
            (daemonmod.omdrop.status, daemonmod.omdrop.start, discovery.awdl_up) = saved

    def test_no_retry_when_awdl_is_already_up_or_phone_out_of_scope(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        calls = []
        saved = (daemonmod.omdrop.status, daemonmod.omdrop.start, discovery.awdl_up)
        daemonmod.omdrop.status = lambda: {"mode": "off", "remaining": None}
        daemonmod.omdrop.start = lambda *a, **k: calls.append(a) or (True, "ok")
        discovery.awdl_up = lambda iface="awdl0": True
        try:
            daemon._tick_omdrop()
            self.assertEqual(calls, [], "an AWDL window that is already up is not touched")
        finally:
            (daemonmod.omdrop.status, daemonmod.omdrop.start, discovery.awdl_up) = saved
        mac_only, _log2 = make_daemon(scope="mac")
        mac_only.omdrop_retry_at = 0.0
        saved = (daemonmod.omdrop.status, daemonmod.omdrop.start, discovery.awdl_up)
        daemonmod.omdrop.status = lambda: {"mode": "off", "remaining": None}
        daemonmod.omdrop.start = lambda *a, **k: calls.append(a) or (True, "ok")
        discovery.awdl_up = lambda iface="awdl0": False
        try:
            mac_only._tick_omdrop()
            self.assertEqual(calls, [], "mac-only scope must never touch the radio")
        finally:
            (daemonmod.omdrop.status, daemonmod.omdrop.start, discovery.awdl_up) = saved


#: `omdrop status --json` measured 2026-10-13 after a 2 h suspend inside a 10 min window:
#: the receiver still runs on the monotonic user timer, the radio half tore itself down.
COLLAPSED = {"receiving": True, "visible": False, "remaining": 262, "mode": "timed",
             "reason": "expired", "rx_proven": True}
LIVE = {"receiving": True, "visible": True, "remaining": None, "mode": "forever",
        "reason": "ok"}


class CollapsedOmdropWindow(unittest.TestCase):
    """An owned window that closes under the daemon is reopened, not trusted forever."""

    def setUp(self):
        self.calls = []
        self.status = dict(COLLAPSED)
        self.bt_calls = []
        self._saved = (daemonmod.omdrop.status, daemonmod.omdrop.start, daemonmod.omdrop.stop,
                       daemonmod.bluetooth.ensure_started)
        daemonmod.omdrop.status = lambda: self.status
        daemonmod.omdrop.start = lambda duration=None, timeout=8.0, ensure_bluetooth=True: (
            self.calls.append(("on", duration)) or (True, "advertising"))
        daemonmod.omdrop.stop = lambda timeout=4.0, force=False: (
            self.calls.append(("off", force)) or (True, "Not receiving"))
        daemonmod.bluetooth.ensure_started = lambda: (
            self.bt_calls.append(1) or (True, True, None))

    def tearDown(self):
        (daemonmod.omdrop.status, daemonmod.omdrop.start, daemonmod.omdrop.stop,
         daemonmod.bluetooth.ensure_started) = self._saved

    def owned(self):
        daemon, log = make_daemon(scope="both")
        daemon.omdrop_owned = True
        daemon.omdrop_window = "forever"
        daemon.bluetooth_owned = daemon.bluetooth_ready = True
        return daemon, log

    def test_forever_run_asks_omdrop_for_forever_not_its_10m_default(self):
        daemon, _log = make_daemon(scope="both")
        self.status = {"receiving": False, "mode": "off", "remaining": None}
        daemon._open_omdrop_window()
        self.assertEqual(self.calls, [("on", "forever")])
        self.assertEqual(daemon.omdrop_window, "forever")

    def test_collapsed_owned_window_is_forced_off_reopened_and_radio_restored(self):
        daemon, log = self.owned()
        daemon.omdrop_retry_at = 0.0
        # After `off` omdrop reports nothing open, so the reopen goes through.
        orig_stop = daemonmod.omdrop.stop

        def stop(timeout=4.0, force=False):
            self.status = {"receiving": False, "mode": "off", "remaining": None,
                           "visible": False, "reason": "stopped"}
            return orig_stop(timeout=timeout, force=force)
        daemonmod.omdrop.stop = stop
        daemon._tick_omdrop()
        self.assertEqual(self.calls, [("off", True), ("on", "forever")])
        self.assertTrue(daemon.omdrop_owned)
        self.assertEqual(self.bt_calls, [1], "bluetooth is brought back before the window")
        self.assertTrue(any("has closed; reopening" in m for m in log.messages("warn")))

    def test_live_owned_window_is_left_alone(self):
        daemon, _log = self.owned()
        daemon.omdrop_retry_at = 0.0
        self.status = dict(LIVE)
        daemon._tick_omdrop()
        self.assertEqual(self.calls, [])
        self.assertEqual(self.bt_calls, [])

    def test_owned_window_check_waits_for_the_interval(self):
        daemon, _log = self.owned()
        daemon.omdrop_retry_at = time.monotonic() + 60
        daemon._tick_omdrop()
        self.assertEqual(self.calls, [])

    def test_fresh_window_is_not_checked_until_a_full_interval_has_passed(self):
        daemon, _log = make_daemon(scope="both")
        self.status = {"receiving": False, "mode": "off", "remaining": None}
        daemon._open_omdrop_window()
        self.assertGreater(daemon.omdrop_retry_at, time.monotonic() + 30)

    def test_someone_elses_collapsed_window_is_not_closed(self):
        from omclip import discovery
        daemon, log = make_daemon(scope="both")
        saved = discovery.awdl_up
        discovery.awdl_up = lambda iface="awdl0": False
        try:
            daemon._tick_omdrop()
            daemon.omdrop_retry_at = 0.0
            daemon._tick_omdrop()                        # same state again: one warn only
            found = daemon._resolve_phone(daemon.by_key["phone"])
        finally:
            discovery.awdl_up = saved
        self.assertEqual(self.calls, [], "not ours: neither closed nor replaced")
        self.assertFalse(daemon.omdrop_owned)
        self.assertEqual(len([m for m in log.messages("warn") if "radio has stopped" in m]), 1)
        self.assertIn("radio has stopped (reason: expired)", found.detail)

    def test_only_an_owned_window_is_closed(self):
        daemon, _log = make_daemon(scope="both")
        calls = []
        saved = daemonmod.omdrop.stop
        daemonmod.omdrop.stop = lambda timeout=4.0: calls.append(timeout) or (True, "closed")
        try:
            daemon._close_omdrop_window()
            self.assertEqual(calls, [], "nothing owned → nothing closed")
            daemon.omdrop_owned = True
            daemon._close_omdrop_window()
        finally:
            daemonmod.omdrop.stop = saved
        self.assertEqual(len(calls), 1)
        self.assertFalse(daemon.omdrop_owned)

class OwnedBluetooth(unittest.TestCase):
    def _stub(self, **names):
        saved = {}
        for name, value in names.items():
            saved[name] = getattr(daemonmod.bluetooth, name)
            setattr(daemonmod.bluetooth, name, value)
        return saved

    def _restore(self, saved):
        for name, value in saved.items():
            setattr(daemonmod.bluetooth, name, value)

    def test_ensure_bluetooth_records_ownership_when_it_started_the_unit(self):
        daemon, _log = make_daemon(scope="both")
        calls = []
        saved = self._stub(ensure_started=lambda: calls.append(1) or (True, True, None))
        try:
            daemon._ensure_bluetooth()
            daemon._ensure_bluetooth()               # idempotent within a run
        finally:
            self._restore(saved)
        self.assertEqual(len(calls), 1)
        self.assertTrue(daemon.bluetooth_owned)
        self.assertFalse(daemon.bluetooth_pre_existing)

    def test_ensure_bluetooth_claims_nothing_when_the_unit_already_ran(self):
        daemon, _log = make_daemon(scope="both")
        saved = self._stub(ensure_started=lambda: (True, False, None))
        try:
            daemon._ensure_bluetooth()
        finally:
            self._restore(saved)
        self.assertFalse(daemon.bluetooth_owned, "a service omclip did not start is not ours")
        self.assertTrue(daemon.bluetooth_pre_existing)

    def test_a_failure_warns_once_per_distinct_reason(self):
        daemon, log = make_daemon(scope="both")
        saved = self._stub(ensure_started=lambda: (False, False, "adapter soft-blocked"))
        try:
            daemon._ensure_bluetooth()
            daemon._ensure_bluetooth()
        finally:
            self._restore(saved)
        self.assertEqual(len([m for m in log.messages("warn") if "bluetooth up" in m]), 1)

    def test_only_an_owned_radio_is_stopped(self):
        daemon, _log = make_daemon(scope="both")
        calls = []
        saved = self._stub(stop=lambda: calls.append(1) or (True, "stopped"),
                           service_active=lambda: True)
        try:
            daemon._release_bluetooth()
            self.assertEqual(calls, [], "not owned → not stopped")
            daemon.bluetooth_owned = True
            daemon._release_bluetooth()
        finally:
            self._restore(saved)
        self.assertEqual(len(calls), 1)
        self.assertFalse(daemon.bluetooth_owned)

    def test_a_pre_existing_service_omdrop_stopped_is_put_back(self):
        # omdrop's own supervisor stops bluetooth.service when its window closes; a
        # service the user was already running must survive `omclip off`.
        daemon, _log = make_daemon(scope="both")
        calls = []
        saved = self._stub(service_active=lambda: False,
                           ensure_running=lambda: calls.append(1) or (True, "started"))
        try:
            daemon.bluetooth_pre_existing = True
            daemon._release_bluetooth()
        finally:
            self._restore(saved)
        self.assertEqual(len(calls), 1)

    def test_a_pre_existing_service_still_running_is_left_alone(self):
        daemon, _log = make_daemon(scope="both")
        calls = []
        saved = self._stub(service_active=lambda: True,
                           ensure_running=lambda: calls.append(1) or (True, "started"))
        try:
            daemon.bluetooth_pre_existing = True
            daemon._release_bluetooth()
        finally:
            self._restore(saved)
        self.assertEqual(calls, [])


class MacResolutionCaching(unittest.TestCase):
    def _stub(self, instances=None, avahi=None, calls=None):
        from omclip import discovery
        saved = (discovery.lan_interface, discovery.resolve_companion_link,
                 discovery.avahi_browse)
        discovery.lan_interface = lambda host=None: (calls.append("iface") if calls is not None
                                                     else "wlp3s0") or "wlp3s0"
        discovery.resolve_companion_link = lambda *a, **k: list(instances or [])
        discovery.avahi_browse = lambda *a, **k: list(avahi or [])
        return saved

    def _restore(self, saved):
        from omclip import discovery
        (discovery.lan_interface, discovery.resolve_companion_link,
         discovery.avahi_browse) = saved

    def test_lookup_runs_at_most_once_per_cache_window(self):
        daemon, _log = make_daemon(scope="mac")
        calls = []
        saved = self._stub(calls=calls)
        try:
            for _ in range(5):
                found = daemon._resolve_mac(daemon.by_key["mac"])
            self.assertEqual(found.address, "localhost")
            self.assertEqual(found.port, 49152, "falls back to mac_host/mac_port")
            self.assertIsNone(found.state)
            self.assertEqual(calls.count("iface"), 1,
                             "a failed lookup must not be retried on every 2 s poll")
        finally:
            self._restore(saved)

    def test_matching_instance_supplies_the_ephemeral_port(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="mac", mac_host="10.0.0.2")
        saved = self._stub([discovery.Instance(discovery.COMPANION, "User's Mac",
                                               "mba.local", 51234,
                                               addresses=["10.0.0.2"])])
        try:
            found = daemon._resolve_mac(daemon.by_key["mac"])
            self.assertEqual((found.address, found.port), ("10.0.0.2", 51234))
            self.assertEqual(daemon.by_key["mac"].label, "User's Mac")
        finally:
            self._restore(saved)

    def test_another_devices_instance_is_ignored(self):
        # The Apple TV on this LAN also answers _companion-link._tcp: its port must never
        # be used for the Mac.
        from omclip import discovery
        daemon, _log = make_daemon(scope="mac", mac_host="10.0.0.2")
        saved = self._stub([discovery.Instance(discovery.COMPANION, "Living Room",
                                               "living-room.local", 49153,
                                               addresses=["10.0.0.218"])])
        try:
            found = daemon._resolve_mac(daemon.by_key["mac"])
            self.assertEqual((found.address, found.port), ("10.0.0.2", 49152))
        finally:
            self._restore(saved)

    def test_host_name_memory_covers_a_missing_address_record(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="mac", mac_host="10.0.0.2")
        with_address = [discovery.Instance(discovery.COMPANION, "MBP", "mba.local", 49152,
                                          addresses=["10.0.0.2"])]
        without_address = [discovery.Instance(discovery.COMPANION, "MBP", "mba.local", 49152)]
        saved = self._stub(with_address)
        try:
            self.assertEqual(daemon._resolve_mac(daemon.by_key["mac"]).port, 49152)
            self.assertEqual(daemon._mac_host_name, "mba.local")
        finally:
            self._restore(saved)
        daemon._mac_mdns_at = 0.0
        saved = self._stub(without_address)         # the A record is missing this time
        try:
            self.assertEqual(daemon._resolve_mac(daemon.by_key["mac"]).port, 49152)
        finally:
            self._restore(saved)

    def test_lookup_retries_once_before_giving_up(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="mac", mac_host="10.0.0.2")
        rounds = []

        def resolver(iface, timeout=3.0, unicast=None):     # noqa: ARG001
            rounds.append(1)
            return ([discovery.Instance(discovery.COMPANION, "MBP", "mba.local", 50001,
                                        addresses=["10.0.0.2"])]
                    if len(rounds) == 2 else [])

        saved = (discovery.lan_interface, discovery.resolve_companion_link, discovery.avahi_browse)
        discovery.lan_interface = lambda host=None: "wlp3s0"
        discovery.resolve_companion_link = resolver
        discovery.avahi_browse = lambda *a, **k: []
        try:
            found = daemon._resolve_mac(daemon.by_key["mac"])
            self.assertEqual(found.port, 50001)
            self.assertEqual(len(rounds), 2)
        finally:
            (discovery.lan_interface, discovery.resolve_companion_link,
             discovery.avahi_browse) = saved

    def test_avahi_is_consulted_when_our_resolver_finds_nothing(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="mac", mac_host="10.0.0.2")
        saved = self._stub([], [discovery.Instance(discovery.COMPANION, "MBP", "mba.local",
                                                  49152, addresses=["10.0.0.2"])])
        daemon._mac_avahi_at = 0.0
        try:
            found = daemon._resolve_mac(daemon.by_key["mac"])
            self.assertEqual(found.port, 49152)
        finally:
            self._restore(saved)


class BulkEvidence(unittest.TestCase):
    """A bulk generation keeps its descriptor (the transfer's address) on disk, once."""

    def bulk_pb(self, unique_id=b"u1"):
        import plistlib
        descriptor = plistlib.dumps({
            "author_data": plistlib.dumps({"unique_id": unique_id, "manager_id": "m",
                                           "client_id": "c"}, fmt=plistlib.FMT_BINARY),
            "bonjour_name": "97b1f7346d19", "message_version": 1}, fmt=plistlib.FMT_BINARY)
        archive = _support.pasteboard_archive(
            items=[{"public.html": {"offset": 0, "size": 1860488, "preferred": True}}],
            extra=descriptor, data_size=1860488, extra_type=1)
        return pasteboard.parse_pasteboard_archive(archive)

    def test_bulk_generation_saves_descriptor_once(self):
        import json
        import shutil
        shutil.rmtree(paths.BULK_DIR, ignore_errors=True)
        daemon, log = make_daemon(scope="both")
        peer = daemon.by_key["phone"]
        pb = self.bulk_pb()
        self.assertTrue(pb["bulk"])
        daemon._handle_pasteboard(peer, pb)
        daemon._handle_pasteboard(peer, pb)              # same generation: no second file
        files = os.listdir(paths.BULK_DIR)
        self.assertEqual(len(files), 1)
        with open(os.path.join(paths.BULK_DIR, files[0])) as fh:
            doc = json.load(fh)
        self.assertEqual(doc["descriptor"]["bonjour_name"], "97b1f7346d19")
        self.assertEqual(doc["descriptor"]["author_data"]["manager_id"], "m")
        self.assertEqual(doc["data_size"], 1860488)
        self.assertEqual(doc["peer"], "phone")
        bulk_lines = [f for lvl, m, f in log.lines if lvl == "info" and "bulk mode" in m]
        self.assertEqual(len(bulk_lines), 1)
        self.assertTrue(bulk_lines[0]["evidence"].endswith("-phone.json"))

    def test_only_the_newest_files_are_kept(self):
        import shutil
        from omclip import state
        shutil.rmtree(paths.BULK_DIR, ignore_errors=True)
        for i in range(state.BULK_KEEP + 3):
            state.save_bulk_evidence("mac", {"i": i}, now=1_700_000_000 + i)
        self.assertEqual(len(os.listdir(paths.BULK_DIR)), state.BULK_KEEP)


class PhoneCandidates(unittest.TestCase):
    """Who gets asked: live AWDL peers, the remembered phone first, never the Mac twice."""

    PHONE = "fe80::6c5f:a3ff:fe96:4a3f"
    MAC = "fe80::e020:b4ff:fef6:65b5"

    def setUp(self):
        from omclip import discovery
        self.discovery = discovery
        self.asked = []
        self.saved = {n: getattr(discovery, n) for n in
                      ("awdl_up", "awdl_live_peers", "awdl_neighbors",
                       "resolve_companion_link_many")}
        discovery.awdl_up = lambda iface="awdl0": True
        discovery.awdl_neighbors = lambda iface="awdl0": ["fe80::stale%d" % i for i in range(30)]

        def many(iface, addresses, timeout=4.0, resend_after=1.5, accept=None):
            self.asked.append(list(addresses))
            out = {}
            if self.MAC in addresses:
                out[self.MAC] = [discovery.Instance(discovery.COMPANION, "CLink-ecc7ec9840d7",
                                                    "8d96b934.local", 49152)]
            if self.PHONE in addresses:
                out[self.PHONE] = [discovery.Instance(discovery.COMPANION, "CLink-5a1a83c849bd",
                                                      "92041405.local", 55289)]
            return out
        discovery.resolve_companion_link_many = many

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(self.discovery, name, value)

    def test_live_peers_replace_the_stale_neighbour_table(self):
        # Measured 2026-10-13: 31 PERMANENT neighbour rows, the iPhone 14th, a cap of 4.
        self.discovery.awdl_live_peers = lambda: [self.MAC, self.PHONE, "fe80::other"]
        daemon, _log = make_daemon(scope="both")
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual((found.address, found.port), (self.PHONE, 55289))
        self.assertEqual(self.asked, [[self.MAC, self.PHONE, "fe80::other"]])

    def test_neighbour_table_is_only_the_fallback(self):
        self.discovery.awdl_live_peers = lambda: None
        daemon, _log = make_daemon(scope="both")
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(found.state, "locked")
        self.assertEqual(len(self.asked[0]), daemonmod.PHONE_MAX_NEIGHBOURS)
        self.assertTrue(all(a.startswith("fe80::stale") for a in self.asked[0]))

    def test_remembered_phone_goes_first_only_while_it_is_live(self):
        self.discovery.awdl_live_peers = lambda: ["fe80::other", self.PHONE]
        daemon, _log = make_daemon(scope="both")
        daemon._phone_last_good = self.PHONE
        daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(self.asked[-1][0], self.PHONE)
        daemon._phone_last_good = "fe80::rotated-away"
        daemon._resolve_phone(daemon.by_key["phone"])
        self.assertNotIn("fe80::rotated-away", self.asked[-1])

    def test_an_awdl_address_found_to_be_the_mac_is_not_asked_again(self):
        self.discovery.awdl_live_peers = lambda: [self.MAC, "fe80::other"]
        daemon, _log = make_daemon(scope="both")
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(found.state, "unreachable")
        self.assertIn(self.MAC, daemon._mac_awdl)
        daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(self.asked[-1], ["fe80::other"])

    def test_known_phone_in_range_but_silent_is_locked_not_mac_only(self):
        self.discovery.awdl_live_peers = lambda: [self.MAC, "fe80::silent-phone"]
        daemon, _log = make_daemon(scope="both")
        daemon._phone_last_good = "fe80::silent-phone"
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(found.state, "locked")
        self.assertIn("in AWDL range", found.detail)
        self.assertEqual(found.seen_address, "fe80::silent-phone")

    def test_resolved_phone_is_saved_for_the_next_run(self):
        from omclip import state
        self.discovery.awdl_live_peers = lambda: [self.PHONE]
        daemon, _log = make_daemon(scope="both")
        daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(state.load_phone().get("last_good"), self.PHONE)


class PhoneResolution(unittest.TestCase):
    def setUp(self):
        self.saved = {}

    def _stub(self, **kwargs):
        from omclip import discovery
        resolver = kwargs.get("resolve_companion_link")
        if resolver is not None:
            # The daemon asks every candidate at once; replay that through the per-address
            # stub in candidate order, stopping where the real query would (`accept`).
            def many(iface, addresses, timeout=4.0, resend_after=1.5, accept=None):
                out = {}
                for address in addresses:
                    found = resolver(iface, timeout=timeout, unicast=address)
                    if found:
                        out[address] = found
                    if accept and any(accept(address, i) for i in found if i.port):
                        break
                return out
            kwargs["resolve_companion_link_many"] = many
        for name, value in kwargs.items():
            self.saved[name] = getattr(discovery, name)
            setattr(discovery, name, value)

    def tearDown(self):
        from omclip import discovery
        for name, value in self.saved.items():
            setattr(discovery, name, value)

    def test_awdl_down_is_unreachable_with_a_fix_hint(self):
        daemon, _log = make_daemon(scope="both")
        self._stub(awdl_up=lambda iface="awdl0": False)
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertIsNone(found.address)
        self.assertEqual(found.state, "unreachable")
        self.assertIn("omdrop", found.detail)

    def test_no_neighbour_is_unreachable(self):
        daemon, _log = make_daemon(scope="both")
        self._stub(awdl_up=lambda iface="awdl0": True, awdl_neighbors=lambda iface="awdl0": [])
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(found.state, "unreachable")
        self.assertIn("AWDL neighbour", found.detail)

    def test_no_companion_link_answer_is_locked(self):
        daemon, _log = make_daemon(scope="both")
        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::1c2d:4a5f:b6c7:d8e9"],
                   resolve_companion_link=lambda *a, **k: [])
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertIsNone(found.address)
        self.assertEqual(found.state, "locked")
        self.assertIn("unlocked", found.detail)
        self.assertIsNone(found.seen_address,
                          "a neighbour that only got asked is not the iPhone's address")
        self.assertIsNone(found.seen_port)

    def test_every_neighbour_is_tried_and_the_first_that_answers_wins(self):
        # Stale static neighbour entries come first on this machine, so asking only
        # neighbours[0] would silently never reach the phone.
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        asked = []

        def resolver(iface, timeout=3.0, unicast=None):     # noqa: ARG001
            asked.append(unicast)
            if unicast == "fe80::good":
                return [discovery.Instance(discovery.COMPANION, "User's iPhone",
                                           "iphone.local", 55289)]
            return []

        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::stale1", "fe80::good",
                                                         "fe80::stale2"],
                   resolve_companion_link=resolver)
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual((found.address, found.port, found.state),
                         ("fe80::good", 55289, None))
        self.assertEqual(asked, ["fe80::stale1", "fe80::good"],
                         "stops at the first neighbour that answers")
        self.assertEqual(daemon.by_key["phone"].label, "User's iPhone")
        self.assertEqual(daemon._phone_last_good, "fe80::good")

    def test_last_good_neighbour_is_asked_first_next_time(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        asked = []
        daemon._phone_last_good = "fe80::good"
        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::stale1", "fe80::good"],
                   resolve_companion_link=lambda iface, timeout=3.0, unicast=None: (
                       asked.append(unicast)
                       or [discovery.Instance(discovery.COMPANION, "P", "h", 1)]))
        daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(asked, ["fe80::good"])

    def test_locked_detail_names_how_many_neighbours_answered_nothing(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::a", "fe80::b"],
                   resolve_companion_link=lambda *a, **k: [])
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual(found.state, "locked")
        self.assertIn("2 AWDL neighbours", found.detail)
        self.assertIsNone(found.seen_address,
                          "asking a neighbour is not identifying the iPhone")

    def test_the_macs_own_awdl_advertisement_is_never_mistaken_for_the_phone(self):
        # Measured 2026-10-13: the Mac answers an AWDL neighbour query as
        # "User's Mac" on port 49152; mirroring it as "phone" would double-poll the
        # same device under two keys.
        from omclip import discovery
        daemon, log = make_daemon(scope="both")
        daemon._mac_host_name = "Users-Mac.local"
        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::mac"],
                   resolve_companion_link=lambda *a, **k: [
                       discovery.Instance(discovery.COMPANION, "User's Mac",
                                          "Users-Mac.local", 49152)])
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertIsNone(found.address)
        self.assertEqual(found.state, "unreachable")
        self.assertIn("only _companion-link peer on awdl0 is the Mac", found.detail)
        self.assertIn("phone_address", found.detail)

    def test_mac_port_plus_a_mac_name_is_rejected_even_without_a_lan_lookup(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        daemon._mac_mdns = None
        daemon._mac_host_name = None
        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::mac"],
                   resolve_companion_link=lambda *a, **k: [
                       discovery.Instance(discovery.COMPANION, "User's Mac",
                                          "Users-Mac.local", 49152)])
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertIsNone(found.address)
        self.assertIn("only _companion-link peer on awdl0 is the Mac", found.detail)

    def test_a_non_mac_awdl_peer_is_still_accepted(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        daemon._mac_host_name = "Users-Mac.local"
        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::mac", "fe80::phone"],
                   resolve_companion_link=lambda iface, timeout=3.0, unicast=None: (
                       [discovery.Instance(discovery.COMPANION, "User's Mac",
                                           "Users-Mac.local", 49152)]
                       if unicast == "fe80::mac" else
                       [discovery.Instance(discovery.COMPANION, "User's iPhone",
                                           "users-iphone.local", 55289)]))
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual((found.address, found.port, found.state),
                         ("fe80::phone", 55289, None))
        self.assertEqual(daemon.by_key["phone"].label, "User's iPhone")

    def test_resolved_phone_uses_its_ephemeral_port(self):
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::1c2d:4a5f:b6c7:d8e9"],
                   resolve_companion_link=lambda *a, **k: [
                       discovery.Instance(discovery.COMPANION, "User's iPhone",
                                          "iphone.local", 55289)])
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertEqual((found.address, found.port, found.state),
                         ("fe80::1c2d:4a5f:b6c7:d8e9", 55289, None))
        self.assertEqual(daemon.by_key["phone"].label, "User's iPhone")

    def test_macs_real_awdl_advertisement_is_rejected_without_a_lan_lookup(self):
        # Measured 2026-10-13: over AWDL the Mac answers as `CLink-a09f420b3ccf` on a
        # UUID host name, *not* as "…'s MacBook Pro", and on its fixed rapportd port.
        # The name never says "Mac", so the fixed port is what has to identify it.
        from omclip import discovery
        daemon, _log = make_daemon(scope="both")
        daemon._mac_mdns = None
        daemon._mac_host_name = None
        self._stub(awdl_up=lambda iface="awdl0": True,
                   awdl_neighbors=lambda iface="awdl0": ["fe80::mac"],
                   resolve_companion_link=lambda *a, **k: [
                       discovery.Instance(discovery.COMPANION, "CLink-a09f420b3ccf",
                                          "8d96b934-374a-42df-853c-128497d7a97f.local",
                                          49152)])
        found = daemon._resolve_phone(daemon.by_key["phone"])
        self.assertIsNone(found.address)
        self.assertEqual(found.state, "unreachable")
        self.assertIn("only _companion-link peer on awdl0 is the Mac", found.detail)


class PhoneAddressPublication(unittest.TestCase):
    """What the phone peer's status object may show (regression, measured 2026-10-14).

    status.json published the Mac's AWDL link-local as the iPhone's `address` — paired with
    the iPhone's ephemeral port — while the same object's `detail` said the only
    `_companion-link` peer on awdl0 was the Mac. An AWDL result that is the Mac must never be
    attributed to the phone, and `address`/`port` must never be a pair from two devices.
    """

    MAC = "fe80::e020:b4ff:fef6:65b5"        # the Mac's AWDL link-local (EUI-64 of e2:20:…)
    PHONE = "fe80::6c5f:a3ff:fe96:4a3f"      # the iPhone's, as remembered in phone.json
    PHONE_PORT = 55289

    class _Session:
        """Stands in for the rapport session so the publication path runs for real."""

        def __init__(self, address, port, *_args, **_kwargs):
            self.address, self.port = address, port

        def open(self):
            pass

        def close(self):
            pass

    def setUp(self):
        from omclip import discovery
        self.discovery = discovery
        self.saved = {n: getattr(discovery, n) for n in
                      ("awdl_up", "awdl_live_peers", "awdl_neighbors",
                       "resolve_companion_link_many")}
        self.saved_session = daemonmod.sessionmod.Session
        daemonmod.sessionmod.Session = self._Session

    def tearDown(self):
        for name, value in self.saved.items():
            setattr(self.discovery, name, value)
        daemonmod.sessionmod.Session = self.saved_session

    def _stub(self, live, answers=None):
        """awdl0 shows `live`; `answers` maps an address to the instances it answers with."""
        answers = answers or {}
        self.discovery.awdl_up = lambda iface="awdl0": True
        self.discovery.awdl_live_peers = lambda: list(live)
        self.discovery.awdl_neighbors = lambda iface="awdl0": list(live)
        self.discovery.resolve_companion_link_many = (
            lambda iface, addresses, timeout=4.0, resend_after=1.5, accept=None:  # noqa: ARG005
            {a: answers[a] for a in addresses if a in answers})

    def _mac_answers(self):
        from omclip import discovery
        return [discovery.Instance(discovery.COMPANION, "CLink-5a1a83c849bd",
                                   "8d96b934-374a-42df-853c-128497d7a97f.local", 49152)]

    def test_the_macs_awdl_address_is_never_published_as_the_iphone(self):
        daemon, _log = make_daemon(scope="both")
        phone = daemon.by_key["phone"]
        self._stub([self.MAC], {self.MAC: self._mac_answers()})
        self.assertFalse(daemon._ensure_session(phone))
        self.assertEqual(phone.state, "unreachable")
        self.assertIn("only _companion-link peer on awdl0 is the Mac", phone.detail)
        self.assertNotEqual(phone.address, self.MAC, "the Mac's AWDL address is not the iPhone's")
        self.assertIsNone(phone.address)
        self.assertIsNone(phone.port)

    def test_a_remembered_address_keeps_its_own_port_when_the_mac_is_the_only_peer(self):
        # The last pair the daemon actually resolved is the only thing worth showing, and it
        # survives a cycle that can only see the Mac.
        daemon, _log = make_daemon(scope="both")
        phone = daemon.by_key["phone"]
        phone.address, phone.port = self.PHONE, self.PHONE_PORT
        daemon._phone_last_good = self.PHONE
        self._stub([self.MAC], {self.MAC: self._mac_answers()})
        daemon._ensure_session(phone)
        published = phone.to_status()
        self.assertEqual((published["address"], published["port"]),
                         (self.PHONE, self.PHONE_PORT))
        self.assertNotIn(self.MAC, (published["address"], published["detail"]))

    def test_a_remembered_address_never_carries_another_addresss_port(self):
        daemon, _log = make_daemon(scope="both")
        phone = daemon.by_key["phone"]
        phone.address, phone.port = "fe80::rotated-away", 44444   # a pair from before a rotation
        daemon._phone_last_good = self.PHONE
        self._stub([self.MAC, self.PHONE])                        # in range, answering nothing
        daemon._ensure_session(phone)
        self.assertEqual(phone.state, "locked")
        self.assertEqual(phone.address, self.PHONE)
        self.assertIsNone(phone.port, "44444 belonged to another address")

    def test_a_locked_phone_still_shows_its_own_address_and_port(self):
        daemon, _log = make_daemon(scope="both")
        phone = daemon.by_key["phone"]
        phone.address, phone.port = self.PHONE, self.PHONE_PORT
        daemon._phone_last_good = self.PHONE
        self._stub([self.MAC, self.PHONE])
        daemon._ensure_session(phone)
        published = phone.to_status()
        self.assertEqual((published["address"], published["port"]),
                         (self.PHONE, self.PHONE_PORT))
        self.assertEqual(published["state"], "locked")
        self.assertIn(self.PHONE, published["detail"])

    def test_the_status_document_never_shows_the_macs_awdl_address_for_the_phone(self):
        daemon, _log = make_daemon(scope="both")
        phone = daemon.by_key["phone"]
        self._stub([self.MAC], {self.MAC: self._mac_answers()})
        daemon._ensure_session(phone)
        doc = daemon.status_doc()
        phone_doc = next(p for p in doc["peers"] if p["key"] == "phone")
        self.assertNotEqual(phone_doc["address"], self.MAC)
        self.assertIsNone(phone_doc["port"])


class PhoneSessionIsTheMac(unittest.TestCase):
    """Guard against a phone session that actually landed on the Mac."""

    class _Session:
        def __init__(self, name):
            self.peer_name = name

    def test_a_mac_session_name_is_dropped(self):
        daemon, _log = make_daemon(scope="both")
        phone = daemon.by_key["phone"]
        phone.session = self._Session("User's Mac")
        self.assertTrue(daemon._phone_peer_is_the_mac(phone))

    def test_the_real_macs_mdns_name_is_dropped(self):
        daemon, _log = make_daemon(scope="both")
        daemon.by_key["mac"].label = "CLink-a09f420b3ccf"
        phone = daemon.by_key["phone"]
        phone.session = self._Session("CLink-a09f420b3ccf")
        self.assertTrue(daemon._phone_peer_is_the_mac(phone))

    def test_an_iphone_session_name_is_kept(self):
        daemon, _log = make_daemon(scope="both")
        daemon.by_key["mac"].label = "User's Mac"
        phone = daemon.by_key["phone"]
        phone.session = self._Session("User's iPhone")
        self.assertFalse(daemon._phone_peer_is_the_mac(phone))

    def test_no_session_is_never_the_mac(self):
        daemon, _log = make_daemon(scope="both")
        self.assertFalse(daemon._phone_peer_is_the_mac(daemon.by_key["phone"]))


class FailureBackoff(unittest.TestCase):
    def test_failures_back_off_and_reset_on_success(self):
        daemon, log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        daemon._fail(peer, "connection reset")
        self.assertEqual(peer.failures, 1)
        self.assertGreater(peer.next_attempt, time.monotonic())
        self.assertEqual(peer.state, "error")
        self.assertIn("peer attempt failed", log.messages("warn"))
        for _ in range(6):
            daemon._fail(peer, "connection reset")
        self.assertEqual(peer.failures, 7)
        self.assertLessEqual(peer.next_attempt - time.monotonic(), 30 * 1.2)
        peer.on_success()
        self.assertEqual(peer.failures, 0)
        self.assertIsNone(peer.last_error)

    def test_repeated_failures_do_not_spam_the_log(self):
        daemon, log = make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        for _ in range(4):
            daemon._fail(peer, "connection reset")
        self.assertEqual(len(log.messages("warn")), 1)
        self.assertEqual(len(log.messages("debug")), 3)


if __name__ == "__main__":
    unittest.main()
