"""mDNS/DNS-SD parsing and the AWDL neighbour helpers (offline, synthetic packets).

Real-world constraints this pins: names may be compressed (the SRV target usually is),
answers arrive in any of answers/additional, and `ip -6 neigh` output is the only way
to find the iPhone's link-local address on `awdl0`.
"""

import socket
import struct
import unittest

import _support  # noqa: F401
from omclip import discovery

INSTANCE = "User's iPhone._companion-link._tcp.local"
HOST = "users-iphone.local"


def _name(text):
    return discovery.encode_name(text)


def _record(name_offset_bytes, rtype, rdata, ttl=4500, rclass=0x8001):
    return (name_offset_bytes + struct.pack(">HHIH", rtype, rclass, ttl, len(rdata)) + rdata)


def response(answer_count, body):
    return struct.pack(">HHHHHH", 0, 0x8400, 0, answer_count, 0, 0) + body


class Names(unittest.TestCase):
    def test_encode_decode_roundtrip(self):
        raw = discovery.encode_name("_companion-link._tcp.local")
        self.assertEqual(raw[-1], 0)
        name, offset = discovery.decode_name(raw, 0)
        self.assertEqual(name, "_companion-link._tcp.local")
        self.assertEqual(offset, len(raw))

    def test_trailing_dot_is_tolerated(self):
        self.assertEqual(discovery.encode_name("a.b."), discovery.encode_name("a.b"))

    def test_compression_pointer_is_followed(self):
        data = discovery.encode_name(HOST) + b"\xc0\x00"        # second name → offset 0
        name, nxt = discovery.decode_name(data, len(data) - 2)
        self.assertEqual(name, HOST)
        self.assertEqual(nxt, len(data))

    def test_build_query_header(self):
        packet = discovery.build_query("_companion-link._tcp.local", discovery.TYPE_PTR)
        self.assertEqual(struct.unpack(">HHHHHH", packet[:12]), (0, 0, 1, 0, 0, 0))
        self.assertEqual(struct.unpack(">HH", packet[-4:]), (discovery.TYPE_PTR, 1))
        name, offset = discovery.decode_name(packet, 12)
        self.assertEqual(name, "_companion-link._tcp.local")
        self.assertEqual(offset, len(packet) - 4)


class Parsing(unittest.TestCase):
    def build_packet(self):
        # Answer 1: PTR _companion-link._tcp.local -> the instance.
        ptr_name = _name("_companion-link._tcp.local")
        first = _record(ptr_name, discovery.TYPE_PTR, _name(INSTANCE))
        # Answer 2: AAAA for the host, so the SRV target can point *back* at it.
        host_name = _name(HOST)
        host_name_offset = 12 + len(first)
        second = _record(host_name, discovery.TYPE_AAAA,
                         socket.inet_pton(socket.AF_INET6, "fe80::1c2d:4a5f:b6c7:d8e9"))
        # Answer 3: SRV for the instance, target name compressed to the AAAA name.
        srv_rdata = (struct.pack(">HHH", 0, 0, 55289)
                     + struct.pack(">H", 0xC000 | host_name_offset))
        third = _record(_name(INSTANCE), discovery.TYPE_SRV, srv_rdata)
        # Answer 4: TXT with two length-prefixed strings.
        txt = b"\x0cmodel=iPhone" + b"\x0aos=version"
        fourth = _record(_name(INSTANCE), discovery.TYPE_TXT, txt)
        return response(4, first + second + third + fourth)

    def test_parse_records(self):
        records = discovery.parse_records(self.build_packet(), "awdl0")
        kinds = {kind for _n, kind, _v, _ttl in records}
        self.assertEqual(kinds, {"PTR", "SRV", "TXT", "AAAA"})
        srv = [value for _n, kind, value, _ttl in records if kind == "SRV"][0]
        self.assertEqual(srv, "%s:55289" % HOST)
        txt = [value for _n, kind, value, _ttl in records if kind == "TXT"][0]
        self.assertEqual(txt, "model=iPhone os=version")
        ptr = [value for _n, kind, value, _ttl in records if kind == "PTR"][0]
        self.assertEqual(ptr, INSTANCE)
        aaaa = [value for _n, kind, value, _ttl in records if kind == "AAAA"][0]
        self.assertTrue(aaaa.endswith("%awdl0"))

    def test_instances_from_records(self):
        instances = discovery.instances_from_records(
            discovery.parse_records(self.build_packet(), "awdl0"), (discovery.COMPANION,))
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0].port, 55289)
        self.assertEqual(instances[0].host, HOST)
        self.assertEqual(instances[0].service, discovery.COMPANION)
        self.assertTrue(instances[0].name)

    def test_short_and_garbage_packets_do_not_raise(self):
        self.assertEqual(discovery.parse_records(b"", "awdl0"), [])
        self.assertEqual(discovery.parse_records(b"\x00" * 6, "awdl0"), [])
        self.assertEqual(discovery.parse_records(b"\x00" * 20, "awdl0"), [])

    def test_ptr_without_srv_yields_nothing(self):
        packet = response(1, _record(_name("_companion-link._tcp.local"),
                                     discovery.TYPE_PTR, _name(INSTANCE)))
        self.assertEqual(discovery.instances_from_records(
            discovery.parse_records(packet, "awdl0")), [])

    def test_avahi_text_output_is_parsed(self):
        text = ("+;wlp3s0;IPv4;_companion-link._tcp;User's Mac\n"
                "=;wlp3s0;IPv4;_companion-link._tcp;User's Mac;_device._tcp.local;"
                "Users-Mac.local;10.0.0.2;49152;rpBA=ABC\n")
        saved = discovery.run
        discovery.run = lambda argv, timeout=None: (0, text)
        try:
            instances = discovery.avahi_browse()
        finally:
            discovery.run = saved
        self.assertEqual(len(instances), 1)
        self.assertEqual(instances[0].port, 49152)
        self.assertEqual(instances[0].host, "Users-Mac.local")

    def test_avahi_failure_is_empty(self):
        saved = discovery.run
        discovery.run = lambda argv, timeout=None: (1, "")
        try:
            self.assertEqual(discovery.avahi_browse(), [])
        finally:
            discovery.run = saved


class Neighbours(unittest.TestCase):
    #: `ip -6 neigh show` (with the dev column).
    OUTPUT = ("fe80::1c2d:4a5f:b6c7:d8e9 dev awdl0 lladdr 5f:cb:2b:66:19:72 REACHABLE\n"
              "fe80::a4f1:22ff:fe33:4455 dev awdl0 lladdr 66:77:88:99:aa:bb STALE\n"
              "192.168.0.5 dev wlp3s0 lladdr 00:11:22:33:44:55 REACHABLE\n")
    #: `ip -6 neigh show dev awdl0` — the form we actually call, which omits the dev column
    #: and may carry trailing whitespace (real output, 2026-10-13).
    FILTERED = ("fe80::e020:b4ff:fef6:65b5 lladdr e2:20:b4:f6:65:b5 PERMANENT \n"
                "fe80::6c5f:a3ff:fe96:4a3f lladdr 6e:5f:a3:96:4a:3f PERMANENT \n")

    def test_parse_neighbours(self):
        rows = discovery.parse_neighbors(self.OUTPUT)
        self.assertEqual(len(rows), 3)
        self.assertEqual(rows[0][1], "5f:cb:2b:66:19:72")
        self.assertEqual(rows[0][2], "REACHABLE")

    def test_filtered_output_is_parsed(self):
        rows = discovery.parse_neighbors(self.FILTERED)
        self.assertEqual([r[0] for r in rows],
                         ["fe80::e020:b4ff:fef6:65b5", "fe80::6c5f:a3ff:fe96:4a3f"])
        self.assertEqual(rows[0][1], "e2:20:b4:f6:65:b5")
        self.assertEqual(rows[0][2], "PERMANENT")

    def test_filtered_output_yields_neighbours(self):
        saved = discovery.run
        discovery.run = lambda argv, timeout=None: (0, self.FILTERED)
        try:
            self.assertEqual(discovery.awdl_neighbors(),
                             ["fe80::e020:b4ff:fef6:65b5", "fe80::6c5f:a3ff:fe96:4a3f"])
        finally:
            discovery.run = saved

    def test_entry_without_state_still_parses(self):
        rows = discovery.parse_neighbors("fe80::1 lladdr aa:bb:cc:dd:ee:ff\n")
        self.assertEqual(rows, [("fe80::1", "aa:bb:cc:dd:ee:ff", None)])

    def test_only_link_local_on_awdl0(self):
        saved = discovery.run
        discovery.run = lambda argv, timeout=None: (0, self.OUTPUT)
        try:
            addresses = discovery.awdl_neighbors()
        finally:
            discovery.run = saved
        self.assertEqual(addresses, ["fe80::1c2d:4a5f:b6c7:d8e9",
                                     "fe80::a4f1:22ff:fe33:4455"])

    def test_no_awdl0_is_not_an_error(self):
        saved = discovery.run
        discovery.run = lambda argv, timeout=None: (1, "Device \"awdl0\" does not exist.")
        try:
            self.assertEqual(discovery.awdl_neighbors(), [])
        finally:
            discovery.run = saved

    def test_awdl_state_reading(self):
        # A missing interface is `down` (no omdrop window), not `unknown`.
        self.assertIs(discovery.awdl_up("omclip-does-not-exist"), False)
        self.assertIn(discovery.awdl_up(), (True, False, None))


class Selection(unittest.TestCase):
    def test_prefers_companion_link(self):
        instances = [discovery.Instance("_airdrop._tcp.local", "Air", "h", 1),
                     discovery.Instance(discovery.COMPANION, "Phone", "h", 2)]
        self.assertEqual(discovery.first_instance(instances).service, discovery.COMPANION)

    def test_skips_instances_without_a_port(self):
        instances = [discovery.Instance(discovery.COMPANION, "Phone", "h", None),
                     discovery.Instance("_airdrop._tcp.local", "Air", "h", 3)]
        self.assertEqual(discovery.first_instance(instances).port, 3)

    def test_nothing_usable(self):
        self.assertIsNone(discovery.first_instance([]))



def _companion_answer(port=55289):
    """PTR + SRV for one `_companion-link` instance (what an iPhone answers over AWDL)."""
    ptr = _record(_name("_companion-link._tcp.local"), discovery.TYPE_PTR, _name(INSTANCE))
    srv = _record(_name(INSTANCE), discovery.TYPE_SRV,
                  struct.pack(">HHH", 0, 0, port) + _name(HOST))
    return response(2, ptr + srv)


class LivePeers(unittest.TestCase):
    """omdrop's `/run/awdl-discoverable/peers.json` → link-local candidates."""

    def write(self, doc):
        import json
        import os
        import tempfile
        fd, path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            fh.write(doc if isinstance(doc, str) else json.dumps(doc))
        self.addCleanup(os.unlink, path)
        return path

    def test_eui64_link_local_matches_the_kernel(self):
        # Measured: AWDL peer 6e:5f:a3:96:4a:3f is the iPhone at fe80::6c5f:a3ff:fe96:4a3f.
        self.assertEqual(discovery.link_local_from_mac("6e:5f:a3:96:4a:3f"),
                         "fe80::6c5f:a3ff:fe96:4a3f")
        self.assertEqual(discovery.link_local_from_mac("5a:25:e3:6f:0e:b8"),
                         "fe80::5825:e3ff:fe6f:eb8")
        for bad in (None, "", "zz:00:00:00:00:00", "00:11:22"):
            self.assertIsNone(discovery.link_local_from_mac(bad))

    def test_fresh_peers_strongest_first_stale_dropped(self):
        path = self.write({
            "e2:20:b4:f6:65:b5": {"addr": "e2:20:b4:f6:65:b5", "rssi": -57, "last_seen": 995},
            "6e:5f:a3:96:4a:3f": {"addr": "6e:5f:a3:96:4a:3f", "rssi": -36, "last_seen": 999},
            "ba:3d:57:e1:78:44": {"addr": "ba:3d:57:e1:78:44", "rssi": -86, "last_seen": 100},
            "junk": "not a peer",
        })
        self.assertEqual(discovery.awdl_live_peers(path, now=1000.0),
                         ["fe80::6c5f:a3ff:fe96:4a3f", "fe80::e020:b4ff:fef6:65b5"])

    def test_missing_or_broken_table_is_none_and_empty_is_empty(self):
        self.assertIsNone(discovery.awdl_live_peers("/nonexistent/peers.json"))
        self.assertIsNone(discovery.awdl_live_peers(self.write("{not json")))
        self.assertEqual(discovery.awdl_live_peers(self.write({}), now=1.0), [])


class UnicastMany(unittest.TestCase):
    """One socket, answers attributed by source address, silent peers asked again."""

    def setUp(self):
        import threading
        self.server = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.server.bind(("::1", 0))
        self.server.settimeout(0.2)
        self.port = self.server.getsockname()[1]
        self.seen = []
        self.ignore_first = True
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.stop.set()
        self.thread.join(2)
        self.server.close()

    def serve(self):
        rounds = 0
        while not self.stop.is_set():
            try:
                _data, peer = self.server.recvfrom(2048)
            except (socket.timeout, OSError):
                continue
            self.seen.append(peer)
            rounds += 1
            # Like the iPhone measured 2026-10-13: the first round (3 queries) is ignored.
            if self.ignore_first and rounds <= 3:
                continue
            self.server.sendto(_companion_answer(), peer)

    def test_silent_first_query_is_asked_again_and_answer_attributed(self):
        records = discovery.query_unicast_many("lo", (discovery.COMPANION,), ["::1"],
                                               timeout=2.0, resend_after=0.3, port=self.port)
        self.assertEqual(list(records), ["::1"])
        instances = discovery.instances_from_records(records["::1"], (discovery.COMPANION,))
        self.assertEqual(instances[0].port, 55289)
        # It returns on the first answer, so the tail of the repeat may not be counted yet.
        self.assertGreater(len(self.seen), 3, "the silent peer was asked a second time")

    def test_returns_early_once_everyone_answered(self):
        import time
        self.ignore_first = False
        start = time.monotonic()
        records = discovery.query_unicast_many("lo", (discovery.COMPANION,), ["::1"],
                                               timeout=3.0, resend_after=2.0, port=self.port)
        self.assertIn("::1", records)
        self.assertLess(time.monotonic() - start, 1.0)
        self.assertLessEqual(len(self.seen), 3, "nobody silent: no second round")

    def test_no_addresses_sends_nothing(self):
        self.assertEqual(discovery.query_unicast_many("lo", (discovery.COMPANION,), []), {})


if __name__ == "__main__":
    unittest.main()
