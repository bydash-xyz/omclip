"""The status document: schema conformance, atomic writes, staleness, no-daemon state."""

import json
import os
import tempfile
import time
import unittest

import _support  # noqa: F401
from omclip import paths, peer as peermod, state, status


def daemon_like_doc():
    """A document the daemon would leave behind (peers included, all keys present)."""
    peer = peermod.Peer("mac")
    peer.address, peer.port = "10.0.0.2", 49152
    peer.set_state("idle")
    peer.last_seen = int(time.time())
    return {
        "schema": 1, "version": "0.1.0", "state": "on", "on": True,
        "since": int(time.time()) - 60, "expires_at": None, "seconds_left": None,
        "scope": ["mac"], "duration": "forever", "stale": False,
        "instance": {"pid": 1, "rss_kb": 14000, "uptime_s": 60, "unit": "omclip.service",
                     "unit_state": "active"},
        "peers": [peer.to_status(),
                  peermod.Peer("phone", in_scope=False).to_status()],
        "clipboard": {"mirrored_total": 3, "last_mirrored_at": int(time.time()),
                      "last_digest": "ab" * 32, "last_uti": "public.utf8-plain-text",
                      "last_bytes": 24, "last_preview": "hello",
                      "skipped": {reason: 0 for reason in status.SKIP_REASONS}},
        "health": {"bluetooth": "off", "bluetooth_detail": "inactive", "awdl": "down",
                   "omdrop": "off", "omdrop_owned": False, "wl_clipboard": True,
                   "wayland": True, "ble_backend": "unavailable", "ble_detail": "no gi"},
        "credentials": [],
        "errors": [],
        "heartbeat": int(time.time()),
    }


class Schema(unittest.TestCase):
    def test_off_document_conforms(self):
        doc = status.build(settings={"scope_list": ["mac"]}, unit="inactive", probe_live=False)
        self.assertEqual(status.validate(doc), [])
        self.assertEqual(doc["state"], "off")
        self.assertFalse(doc["on"])
        self.assertIsNone(doc["since"])
        self.assertTrue(all(p["state"] == "disabled" for p in doc["peers"]))
        self.assertEqual([p["key"] for p in doc["peers"]], ["mac", "phone"])

    def test_daemon_document_conforms(self):
        self.assertEqual(status.validate(daemon_like_doc()), [])

    def test_clipboard_last_file_is_optional_but_typed(self):
        """Additive: absent still conforms, present is checked, wrong types are caught."""
        doc = daemon_like_doc()
        self.assertEqual(status.validate(doc), [], "a build that predates the field")
        doc["clipboard"]["last_file"] = {"name": "IMG_1739.HEIC",
                                         "path": "/home/user/Downloads/IMG_1739.HEIC",
                                         "bytes": 1631561}
        self.assertEqual(status.validate(doc), [])
        doc["clipboard"]["last_file"] = None
        self.assertEqual(status.validate(doc), [])
        doc["clipboard"]["last_file"] = {"name": 7, "path": None, "bytes": "big"}
        problems = status.validate(doc)
        for key in ("name", "path", "bytes"):
            self.assertTrue(any("clipboard.last_file.%s" % key in p for p in problems),
                            "clipboard.last_file.%s must be type-checked" % key)
        doc["clipboard"]["last_file"] = "IMG_1739.HEIC"
        self.assertTrue(any("clipboard.last_file must be an object or null" in p
                            for p in status.validate(doc)))

    def test_format_bytes_reads_like_the_prose(self):
        self.assertEqual(status.format_bytes(48), "48 B")
        self.assertEqual(status.format_bytes(2000000), "2.0 MB")
        self.assertEqual(status.format_bytes(1631561), "1.6 MB")
        self.assertEqual(status.format_bytes(312874), "312.9 kB")
        self.assertEqual(status.format_bytes(None), "?")

    def test_validator_catches_broken_documents(self):
        broken = daemon_like_doc()
        broken["state"] = "happy"
        broken["on"] = "yes"
        broken["peers"][0]["state"] = "busy"
        broken["clipboard"]["skipped.pop"] = None
        del broken["clipboard"]["skipped"]["unchanged"]
        broken["health"]["bluetooth"] = "fine"
        problems = status.validate(broken)
        self.assertTrue(any("state must be one of" in p for p in problems))
        self.assertTrue(any("on must be a bool" in p for p in problems))
        self.assertTrue(any("peers[0].state" in p for p in problems))
        self.assertTrue(any("skipped.unchanged" in p for p in problems))
        self.assertTrue(any("health.bluetooth" in p for p in problems))

    def test_every_skip_reason_is_reported(self):
        doc = status.build(settings={"scope_list": ["mac"]}, unit="inactive", probe_live=False)
        self.assertEqual(set(doc["clipboard"]["skipped"]), set(status.SKIP_REASONS))
        self.assertEqual(set(status.SKIP_REASONS),
                         {"unchanged", "bulk", "empty", "local_echo", "oversize", "nodata"})


class DaemonViewMerge(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.file = os.path.join(self.tmp.name, "status.json")
        self._saved = paths.STATUS_FILE
        paths.STATUS_FILE = self.file

    def tearDown(self):
        paths.STATUS_FILE = self._saved
        self.tmp.cleanup()

    def test_running_daemon_view_is_used(self):
        doc = daemon_like_doc()
        state.write_json(self.file, doc)
        built = status.build(settings={"scope_list": ["mac"]}, unit="active", probe_live=False)
        self.assertEqual(built["state"], "on")
        self.assertTrue(built["on"])
        self.assertEqual(built["peers"][0]["state"], "idle")
        self.assertFalse(built["stale"])

    def test_stale_heartbeat_is_flagged(self):
        doc = daemon_like_doc()
        doc["heartbeat"] = int(time.time()) - 30
        state.write_json(self.file, doc)
        built = status.build(settings={"scope_list": ["mac"]}, unit="active", probe_live=False)
        self.assertTrue(built["stale"])
        self.assertEqual(built["state"], "on", "the heartbeat flags, it does not rewrite state")

    def test_missing_document_while_active_is_starting(self):
        built = status.build(settings={"scope_list": ["mac"]}, unit="active", probe_live=False,
                             desired={"duration": "10m"})
        self.assertEqual(built["state"], "starting")
        self.assertTrue(built["on"])
        self.assertTrue(built["stale"], "no heartbeat yet")
        self.assertEqual(built["duration"], "10m")

    def test_active_unit_with_old_off_document_is_starting(self):
        # When service was stopped earlier, status.json has state: "off", on: False.
        # When the unit is started, status.build must report starting, on: True.
        state.write_json(self.file, {"state": "off", "on": False, "peers": [], "clipboard": {"mirrored_total": 0}})
        built = status.build(settings={"scope_list": ["mac"]}, unit="active", probe_live=False,
                             desired={"duration": "10m"})
        self.assertEqual(built["state"], "starting")
        self.assertTrue(built["on"])

    def test_inactive_unit_ignores_a_stale_document(self):
        state.write_json(self.file, daemon_like_doc())
        built = status.build(settings={"scope_list": ["mac"]}, unit="inactive", probe_live=False)
        self.assertEqual(built["state"], "off")
        self.assertFalse(built["on"])
        self.assertTrue(all(p["state"] == "disabled" for p in built["peers"]))

    def test_seconds_left_is_computed_live(self):
        doc = daemon_like_doc()
        doc["expires_at"] = int(time.time()) + 120
        doc["seconds_left"] = 999999
        state.write_json(self.file, doc)
        built = status.build(settings={"scope_list": ["mac"]}, unit="active", probe_live=False)
        self.assertLessEqual(built["seconds_left"], 120)
        self.assertGreater(built["seconds_left"], 100)

    def test_scope_comes_from_desired_state(self):
        doc = daemon_like_doc()
        doc["scope"] = ["mac", "phone"]
        state.write_json(self.file, doc)
        built = status.build(settings={"scope_list": ["mac"]}, unit="active", probe_live=False)
        self.assertEqual(built["scope"], ["mac", "phone"])

    def test_consolidate_peers_deduplicates_mac_on_both_transports(self):
        doc = daemon_like_doc()
        # Simulate duplicate Mac: both mac and phone peers reporting as the Mac
        doc["peers"][0]["label"] = "User's Mac"
        doc["peers"][0]["address"] = "10.0.0.2"
        doc["peers"][0]["port"] = 49152
        doc["peers"][1]["label"] = "User's Mac"
        doc["peers"][1]["address"] = "fe80::mac"
        doc["peers"][1]["port"] = 49152
        doc["peers"][1]["state"] = "idle"
        state.write_json(self.file, doc)
        built = status.build(unit="active", probe_live=False)
        # Mac peer retains primary LAN address
        self.assertEqual(built["peers"][0]["label"], "User's Mac")
        self.assertEqual(built["peers"][0]["address"], "10.0.0.2")
        # Phone peer is consolidated/reset to iPhone unreachable, not duplicate Mac
        self.assertEqual(built["peers"][1]["label"], "iPhone")
        self.assertEqual(built["peers"][1]["state"], "unreachable")
        self.assertIsNone(built["peers"][1]["address"])


class AtomicWrite(unittest.TestCase):
    def test_write_and_read_back(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "status.json")
            doc = daemon_like_doc()
            status.write(doc, path)
            with open(path, "r", encoding="utf-8") as fh:
                self.assertEqual(json.load(fh)["state"], "on")
            self.assertEqual(status.read(path)["schema"], 1)
            self.assertEqual(os.listdir(tmp), ["status.json"], "temp file must be renamed away")

    def test_repeated_writes_do_not_leak_temp_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "status.json")
            for _ in range(20):
                state.write_json(path, {"n": 1})
            self.assertEqual(os.listdir(tmp), ["status.json"])

    def test_replace_is_atomic_for_readers(self):
        # A reader must never see a partial document: every observed file parses.
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "status.json")
            state.write_json(path, {"state": "off"})
            for index in range(50):
                state.write_json(path, {"state": "on", "n": index, "pad": "x" * 4096})
                with open(path, "r", encoding="utf-8") as fh:
                    self.assertIn(json.load(fh)["state"], ("off", "on"))

    def test_missing_file_reads_as_none(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertIsNone(status.read(os.path.join(tmp, "nope.json")))
            self.assertIsNone(state.read_json(os.path.join(tmp, "nope.json")))


class ProcessFacts(unittest.TestCase):
    def test_own_process_rss_and_uptime(self):
        self.assertGreater(status.proc_rss_kb(os.getpid()), 0)
        self.assertGreater(status.proc_uptime_s(os.getpid()), -1)

    def test_unknown_pid(self):
        self.assertIsNone(status.proc_rss_kb(10 ** 9))
        self.assertIsNone(status.proc_uptime_s(10 ** 9))


class CryptoHealth(unittest.TestCase):
    """health.crypto_backend/crypto_detail: the daemon's AEAD implementation, or unknown."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.file = os.path.join(self.tmp.name, "status.json")
        self._saved = paths.STATUS_FILE
        paths.STATUS_FILE = self.file

    def tearDown(self):
        paths.STATUS_FILE = self._saved
        self.tmp.cleanup()

    def test_no_daemon_reports_unknown(self):
        doc = status.build(settings={"scope_list": ["mac"]}, unit="inactive", probe_live=False)
        self.assertEqual(doc["health"]["crypto_backend"], "unknown")
        self.assertIsNone(doc["health"]["crypto_detail"])
        self.assertEqual(status.validate(doc), [])

    def test_the_daemon_document_is_the_truth(self):
        daemon_doc = daemon_like_doc()
        # Both pairs as the daemon writes them: inside health and at the top level.
        daemon_doc["ble_backend"] = "monitor"
        daemon_doc["crypto_backend"] = "python"
        daemon_doc["crypto_detail"] = "disabled by OMCLIP_CRYPTO='py'"
        state.write_json(self.file, daemon_doc)
        built = status.build(settings={"scope_list": ["mac"]}, unit="active", probe_live=False)
        self.assertEqual(built["health"]["crypto_backend"], "python")
        self.assertEqual(built["health"]["crypto_detail"], "disabled by OMCLIP_CRYPTO='py'")
        self.assertEqual(built["health"]["ble_backend"], "monitor", "the ble pair is untouched")
        self.assertEqual(status.validate(built), [])

    def test_a_document_without_the_keys_still_conforms(self):
        # Additive keys: a document from a build that predates them leaves the live
        # placeholder in place and is not a schema violation.
        state.write_json(self.file, daemon_like_doc())
        built = status.build(settings={"scope_list": ["mac"]}, unit="active", probe_live=False)
        self.assertEqual(built["health"]["crypto_backend"], "unknown")
        self.assertIsNone(built["health"]["crypto_detail"])
        self.assertEqual(status.validate(built), [])

    def test_the_validator_checks_the_values_when_present(self):
        doc = daemon_like_doc()
        doc["health"]["crypto_backend"] = "openssl"
        doc["health"]["crypto_detail"] = 7
        problems = status.validate(doc)
        self.assertTrue(any("health.crypto_backend" in p for p in problems))
        self.assertTrue(any("health.crypto_detail" in p for p in problems))
        doc["health"]["crypto_backend"] = "libcrypto"
        doc["health"]["crypto_detail"] = None
        self.assertEqual(status.validate(doc), [])


if __name__ == "__main__":
    unittest.main()
