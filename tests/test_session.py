"""The hardened session: request correlation, events, deadlines, failure modes.

These tests drive the client against a fake peer over a real socket, including a full
`open()` (Pair-Verify + `_systemInfo` announce) against a loopback listener, because the
interesting failures are all about *timing* and *matching*:

* an unsolicited frame must never be mistaken for the reply and must never be dropped,
* a lost reply must fail inside the deadline (never the reference's 8 × 4 s backstop),
* EOF/reset must raise `PeerGone` immediately so the daemon can back off,
* a channel desync must be fatal for the session, not silently decoded as garbage,
* a shutdown flag must abort a wait inside ~a quarter second.
"""

import socket
import threading
import time
import unittest

import _support
from omclip import crypto, pasteboard, protocol, session

FRAME_OPACK = protocol.FRAME_OPACK


def _aad(frame_type, body):
    return bytes([frame_type]) + len(body).to_bytes(3, "big")


class FakePeer(threading.Thread):
    """Loopback `rapportd`: Pair-Verify, `_systemInfo` reply, then scripted responses."""

    def __init__(self, respond=None, authenticate=True, close_after_auth=False,
                 wrong_key=False, announce_reply=None):
        super().__init__(daemon=True)
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.port = self.listener.getsockname()[1]
        self.respond = respond
        self.authenticate = authenticate
        self.close_after_auth = close_after_auth
        self.wrong_key = wrong_key
        self.announce_reply = announce_reply
        self.requests = []
        self.error = None
        self.authenticated = False
        self.m1_tlv = None

    def run(self):
        try:
            conn, _addr = self.listener.accept()
            conn.settimeout(10.0)
            self.sock = conn
            if not self.authenticate:
                return
            self._pair_verify(conn)
            if self.close_after_auth:
                conn.close()
                return
            self._serve(conn)
            conn.close()
        except Exception as exc:                       # noqa: BLE001 - asserted by tests
            self.error = exc

    # -- protocol ----------------------------------------------------------

    def _pair_verify(self, conn):
        ft, body = protocol.recv_frame(conn)
        assert ft == protocol.FRAME_M1
        obj, _ = crypto.opack_decode(body)
        self.m1_tlv = crypto.tlv8_decode(obj["_pd"])
        client_pub = self.m1_tlv[0x03]
        server_sk, server_pub = crypto.new_ephemeral()
        shared = crypto.x25519(server_sk, client_pub)
        self.shared = shared
        key = crypto.hkdf_sha512(shared, protocol.SALT, protocol.INFO, 32)
        conn.sendall(protocol.frame(protocol.FRAME_PV, crypto.opack_encode(
            {"_pd": crypto.tlv8_encode([
                (0x03, server_pub),
                (0x05, crypto.chacha20poly1305_encrypt(
                    key, protocol.nonce(b"PV-Msg02"),
                    crypto.tlv8_encode([(0x0A, b"\x22" * 64)]))),
                (0x06, b"\x02")])})))
        _ft, body3 = protocol.recv_frame(conn)
        tlv3 = crypto.tlv8_decode(crypto.opack_decode(body3)[0]["_pd"])
        self.m3_inner = crypto.tlv8_decode(
            crypto.chacha20poly1305_decrypt(key, protocol.nonce(b"PV-Msg03"), tlv3[0x05]))
        conn.sendall(protocol.frame(protocol.FRAME_PV, crypto.opack_encode(
            {"_pd": crypto.tlv8_encode([(0x06, b"\x04")])})))
        self.authenticated = True
        # From here on everything is sealed; a "wrong key" peer proves the desync path.
        self.channel = protocol.ContentChannel(
            b"\x00" * 32 if self.wrong_key else shared, client_role=False)

    def _serve(self, conn):
        while True:
            try:
                ft, body = protocol.recv_frame(conn)
            except (protocol.PeerGone, OSError):
                return
            obj = crypto.opack_decode(self.channel.open(body, aad=_aad(ft, body)))[0]
            self.requests.append(obj)
            if obj.get("_i") == "_systemInfo" and self.announce_reply is not False:
                self._send(conn, {"_t": 3, "_x": obj.get("_x"),
                                  "_c": self.announce_reply or {"name": "User's Mac",
                                                                "_idsID": "PEER"}})
                continue
            if self.respond is None:
                continue                                # deliberately never reply
            content = self.respond(obj)
            if content is None:
                continue
            self._send(conn, {"_t": 3, "_x": obj.get("_x"), "_c": content})

    def _send(self, conn, obj):
        body = crypto.opack_encode(obj)
        protocol.send_frame(conn, FRAME_OPACK, body, self.channel)

def _session(peer, **kwargs):
    return session.Session("127.0.0.1", peer.port, b"\x11" * 32, "ab" * 32, "IDS-TEST",
                           **kwargs)


class OpenAndRequest(unittest.TestCase):
    def test_open_authenticates_announces_and_polls(self):
        archive = _support.inline_text("Braun : Designed to Keep")
        peer = FakePeer(respond=lambda obj: {"rAdvPayload": protocol.HANDOFF_ADV_PAYLOAD,
                                             "rActPayload": archive})
        peer.start()
        sess = _session(peer, request_timeout=3.0)
        try:
            sess.open()
            self.assertTrue(peer.authenticated)
            self.assertEqual(peer.m1_tlv[0x19], b"\x01")
            time.sleep(0.1)
            resp, pb = sess.payload_request()
            self.assertEqual(resp["_c"]["rAdvPayload"], protocol.HANDOFF_ADV_PAYLOAD)
            self.assertEqual(pb["items"][0]["types"]["public.utf8-plain-text"]["size"], 24)
            uti, data = pasteboard.best_representation(pb)
            self.assertEqual((uti, data), ("public.utf8-plain-text", b"Braun : Designed to Keep"))
            # The announce carried our _idsID, and its reply was buffered, not lost.
            announce = peer.requests[0]
            self.assertEqual(announce["_i"], "_systemInfo")
            self.assertEqual(announce["_c"]["_idsID"], "IDS-TEST")
            self.assertTrue(any(ev["obj"].get("_t") == 3 for ev in sess.events))
            self.assertEqual(sess.peer_name, "User's Mac")
        finally:
            sess.close()
            peer.join(timeout=5)
            peer.listener.close()
        self.assertIsNone(peer.error, peer.error)

    def test_open_fails_when_peer_closes_after_auth(self):
        peer = FakePeer(close_after_auth=True)
        peer.start()
        sess = _session(peer)
        sess.open()                                    # auth succeeded; peer then vanished
        try:
            with self.assertRaises(protocol.PeerGone):
                sess.payload_request()
        finally:
            sess.close()
            peer.join(timeout=5)
            peer.listener.close()


class RequestLoop(unittest.TestCase):
    def setUp(self):
        self.shared = bytes(range(32))
        self.client, self.server_sock = socket.socketpair()
        self.client.settimeout(5.0)
        self.server_sock.settimeout(5.0)
        self.sess = session.Session("h", 1, b"\x00" * 32, "00" * 32, "IDS")
        self.sess.sock = self.client
        self.sess.channel = protocol.ContentChannel(self.shared)
        self.sess.xid = 1
        self.sess.last_exchange = time.monotonic()
        self.chan = protocol.ContentChannel(self.shared, client_role=False)
        self.threads = []

    def tearDown(self):
        # Unblock the fake peer's reader first, otherwise each join waits out its 5 s
        # socket timeout and the suite takes half a minute for no reason.
        self.sess.close()
        try:
            self.server_sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        for thread in self.threads:
            thread.join(timeout=5)
        self.server_sock.close()

    def _server(self, handler):
        def run():
            while True:
                try:
                    ft, body = protocol.recv_frame(self.server_sock)
                except (protocol.PeerGone, OSError):
                    return
                obj = crypto.opack_decode(self.chan.open(body, aad=_aad(ft, body)))[0]
                handler(obj)
        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.threads.append(thread)

    def _send(self, obj):
        body = crypto.opack_encode(obj)
        protocol.send_frame(self.server_sock, FRAME_OPACK, body, self.chan)

    def test_reply_is_matched_past_unsolicited_frames(self):
        seen = []

        def handler(obj):
            if seen:
                return
            seen.append(obj)
            self._send({"_i": "_systemInfoUpdate", "_t": 1, "_c": {"_sigPD": b"\x00"}})
            self._send({"_t": 3, "_x": 99, "_c": {"stray": True}})
            self._send({"_t": 3, "_x": obj["_x"], "_c": {"ok": True}})

        self._server(handler)
        resp = self.sess.request("com.apple.handoff.payload-request", {"a": 1}, deadline=3.0)
        self.assertEqual(resp["_c"], {"ok": True})
        self.assertEqual(len(self.sess.events), 2)
        self.assertEqual(self.sess.events[0]["obj"]["_i"], "_systemInfoUpdate")

    def test_missing_reply_fails_inside_the_deadline(self):
        self._server(lambda obj: None)                 # never answers
        start = time.monotonic()
        with self.assertRaises(protocol.RequestTimeout):
            self.sess.request("_systemInfo", {}, deadline=0.6)
        elapsed = time.monotonic() - start
        self.assertLess(elapsed, 1.5, "must bound total latency, not retry 8 x 4 s")

    def test_eof_raises_peer_gone(self):
        def handler(_obj):
            self.server_sock.close()

        self._server(handler)
        with self.assertRaises(protocol.PeerGone):
            self.sess.request("_systemInfo", {}, deadline=2.0)

    def test_peer_error_response_raises(self):
        def handler(obj):
            self._send({"_t": 3, "_x": obj["_x"], "_ec": 58828, "_em": "IDS device not found"})

        self._server(handler)
        with self.assertRaises(protocol.PeerError) as ctx:
            self.sess.request("com.apple.handoff.payload-request", {}, deadline=2.0)
        self.assertIn("58828", str(ctx.exception))

    def test_channel_desync_is_fatal(self):
        def handler(_obj):
            other = protocol.ContentChannel(b"\xff" * 32, client_role=False)
            body = crypto.opack_encode({"_t": 3, "_x": 2, "_c": {}})
            protocol.send_frame(self.server_sock, FRAME_OPACK, body, other)

        self._server(handler)
        with self.assertRaises(protocol.PeerGone) as ctx:
            self.sess.request("_systemInfo", {}, deadline=2.0)
        self.assertIn("desync", str(ctx.exception))

    def test_stop_flag_aborts_a_wait_quickly(self):
        self._server(lambda obj: None)
        flag = {"stop": False}
        threading.Timer(0.2, lambda: flag.update(stop=True)).start()
        start = time.monotonic()
        with self.assertRaises(protocol.StopRequested):
            self.sess.request("_systemInfo", {}, deadline=5.0,
                              should_stop=lambda: flag["stop"])
        self.assertLess(time.monotonic() - start, 1.0)


class Recycling(unittest.TestCase):
    def test_idle_session_is_recycled(self):
        sess = session.Session("h", 1, b"\x00" * 32, "00" * 32, "IDS")
        sess.last_exchange = time.monotonic() - session.IDLE_RECYCLE_S - 1
        self.assertTrue(sess.recycle_needed())
        sess.last_exchange = time.monotonic()
        self.assertFalse(sess.recycle_needed())
        sess.last_exchange = None
        self.assertTrue(sess.recycle_needed())

    def test_close_is_idempotent(self):
        sess = session.Session("h", 1, b"\x00" * 32, "00" * 32, "IDS")
        left, right = socket.socketpair()
        sess.sock = left
        sess.close()
        sess.close()
        self.assertIsNone(sess.sock)
        right.close()


if __name__ == "__main__":
    unittest.main()
