"""Framing, content channel and Pair-Verify.

`pair_verify` is exercised against a fake `rapportd` built from the same primitives —
that pins the M1 shape (the `0x19` AppFlags TLV), the M2/M3 key derivation, the exact
signed message and the M4 error path. It is a shape test, not an interop test: real
interop is the live Mac/iPhone check in the journal.
"""

import socket
import threading
import unittest

import _support  # noqa: F401
from omclip import crypto, protocol


def socketpair():
    left, right = socket.socketpair()
    left.settimeout(5.0)
    right.settimeout(5.0)
    return left, right


class Framing(unittest.TestCase):
    def test_frame_roundtrip(self):
        left, right = socketpair()
        try:
            left.sendall(protocol.frame(protocol.FRAME_OPACK, b"hello"))
            self.assertEqual(protocol.recv_frame(right), (8, b"hello"))
        finally:
            left.close()
            right.close()

    def test_length_is_three_bytes_big_endian(self):
        self.assertEqual(protocol.frame(6, b"abc")[:4], b"\x06\x00\x00\x03")

    def test_eof_raises_peer_gone(self):
        left, right = socketpair()
        try:
            left.close()
            with self.assertRaises(protocol.PeerGone):
                protocol.recv_frame(right)
        finally:
            right.close()

    def test_truncated_body_raises_peer_gone(self):
        left, right = socketpair()
        try:
            left.sendall(b"\x08\x00\x00\x10abc")     # promises 16 bytes
            left.close()
            with self.assertRaises(protocol.PeerGone):
                protocol.recv_frame(right)
        finally:
            right.close()


class ContentChannelTests(unittest.TestCase):
    SHARED = bytes(range(32))

    def test_client_and_server_keys_are_symmetric(self):
        client = protocol.ContentChannel(self.SHARED, client_role=True)
        server = protocol.ContentChannel(self.SHARED, client_role=False)
        blob = client.seal(b"payload", aad=b"hdr")
        self.assertEqual(server.open(blob, aad=b"hdr"), b"payload")
        blob = server.seal(b"reply", aad=b"hdr")
        self.assertEqual(client.open(blob, aad=b"hdr"), b"reply")

    def test_counter_is_per_direction_and_strict(self):
        client = protocol.ContentChannel(self.SHARED)
        server = protocol.ContentChannel(self.SHARED, client_role=False)
        first = client.seal(b"a")
        second = client.seal(b"b")
        self.assertNotEqual(first, second)
        self.assertEqual(server.open(first), b"a")
        self.assertEqual(server.open(second), b"b")
        with self.assertRaises(ValueError):
            server.open(first)                        # counter already advanced

    def test_aad_mismatch_is_rejected(self):
        client = protocol.ContentChannel(self.SHARED)
        server = protocol.ContentChannel(self.SHARED, client_role=False)
        blob = client.seal(b"x", aad=protocol.frame(8, b"x")[:4])
        with self.assertRaises(ValueError):
            server.open(blob, aad=b"\x08\x00\x00\xff")


class SystemInfo(unittest.TestCase):
    def test_ids_id_is_announced(self):
        info = protocol.build_system_info("11111111-2222-3333-4444-555555555555",
                                          name="air", dev_id="abc123")
        self.assertEqual(info["_idsID"], "11111111-2222-3333-4444-555555555555")
        self.assertEqual(info["_i"], "abc123")
        self.assertEqual(info["name"], "air")

    def test_device_info_id_is_stable_and_12_hex(self):
        dummy_pk = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        first = protocol.device_info_id(dummy_pk)
        self.assertEqual(first, protocol.device_info_id(dummy_pk))
        self.assertEqual(len(first), 12)
        int(first, 16)

    def test_payload_request_shape(self):
        body, _ = crypto.opack_decode(protocol.payload_request_body("pbpaste2", xid=7))
        self.assertEqual(body["_i"], "com.apple.handoff.payload-request")
        self.assertEqual(body["_x"], 7)
        self.assertEqual(body["_c"]["rClientCommand"], "pbpaste2")
        self.assertEqual(body["_c"]["rIdentifier"], "")
        self.assertEqual(body["_c"]["rAdvPayload"], protocol.HANDOFF_ADV_PAYLOAD)


class FakeRapportd(threading.Thread):
    """The smallest peer that can complete Pair-Verify (M1→M4)."""

    def __init__(self, sock, ed_pk=None, fail=None):
        super().__init__(daemon=True)
        self.sock, self.fail = sock, fail
        self.m1_tlv = None
        self.m3_inner = None
        self.server_pub = None
        self.error = None

    def run(self):
        try:
            ft, body = protocol.recv_frame(self.sock)
            self.assert_frame = ft
            self.m1_frame = ft
            obj, _ = crypto.opack_decode(body)
            self.m1_tlv = crypto.tlv8_decode(obj["_pd"])
            client_pub = self.m1_tlv[0x03]
            server_sk, server_pub = crypto.new_ephemeral()
            self.server_pub = server_pub
            self.shared = crypto.x25519(server_sk, client_pub)
            key = crypto.hkdf_sha512(self.shared, protocol.SALT, protocol.INFO, 32)
            proof = crypto.tlv8_encode([(0x0A, b"\x11" * 64)])
            m2 = protocol.frame(protocol.FRAME_PV, crypto.opack_encode(
                {"_pd": crypto.tlv8_encode([(0x03, server_pub),
                                            (0x05, crypto.chacha20poly1305_encrypt(
                                                key, protocol.nonce(b"PV-Msg02"), proof)),
                                            (0x06, b"\x02")])}))
            self.sock.sendall(m2)
            _ft, body3 = protocol.recv_frame(self.sock)
            tlv3 = crypto.tlv8_decode(crypto.opack_decode(body3)[0]["_pd"])
            inner = crypto.chacha20poly1305_decrypt(key, protocol.nonce(b"PV-Msg03"),
                                                    tlv3[0x05])
            self.m3_inner = crypto.tlv8_decode(inner)
            if self.fail:
                m4 = crypto.tlv8_encode([(0x06, b"\x04"), (0x07, bytes([self.fail]))])
            else:
                m4 = crypto.tlv8_encode([(0x06, b"\x04")])
            self.sock.sendall(protocol.frame(protocol.FRAME_PV,
                                             crypto.opack_encode({"_pd": m4})))
        except Exception as exc:                       # noqa: BLE001 - surfaced by the test
            self.error = exc


class PairVerify(unittest.TestCase):
    ED_SK = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")

    def test_full_handshake(self):
        client, server = socketpair()
        peer = FakeRapportd(server)
        peer.start()
        try:
            shared = protocol.pair_verify(client, self.ED_SK, timeout=5.0)
        finally:
            client.close()
        peer.join(timeout=5)
        self.assertIsNone(peer.error, peer.error)
        # The 0x19 AppFlags=1 TLV is the whole trick: without it the peer takes the
        # default variant and M3 is rejected.
        self.assertEqual(peer.m1_tlv[0x19], b"\x01")
        self.assertEqual(peer.m1_tlv[0x06], b"\x01")
        self.assertEqual(len(peer.m1_tlv[0x03]), 32)
        self.assertIn(0x0A, peer.m3_inner)
        self.assertNotIn(0x01, peer.m3_inner, "M3 on the RPIdentity path is signature-only")
        # The signature is over client_eph_pub ‖ server_eph_pub (no identifier).
        m1_client_pub = peer.m1_tlv[0x03]
        self.assertEqual(peer.m3_inner[0x0A],
                         crypto.ed25519_sign(self.ED_SK, m1_client_pub + peer.server_pub))
        self.assertEqual(shared, peer.shared,
                         "client and server must derive the same X25519 secret")
        server.close()

    def test_m4_error_raises_auth_failed(self):
        client, server = socketpair()
        peer = FakeRapportd(server, fail=0x02)
        peer.start()
        try:
            with self.assertRaises(protocol.AuthFailed) as ctx:
                protocol.pair_verify(client, self.ED_SK, timeout=5.0)
            self.assertIn("0x02", str(ctx.exception))
        finally:
            client.close()
            server.close()

    def test_bad_m2_is_auth_failed(self):
        client, server = socketpair()

        def junk():
            protocol.recv_frame(server)
            server.sendall(protocol.frame(protocol.FRAME_PV,
                                          crypto.opack_encode({"_pd": crypto.tlv8_encode(
                                              [(0x06, b"\x02")])})))

        thread = threading.Thread(target=junk, daemon=True)
        thread.start()
        try:
            with self.assertRaises(protocol.AuthFailed):
                protocol.pair_verify(client, self.ED_SK, timeout=5.0)
        finally:
            client.close()
            server.close()
        thread.join(timeout=5)


if __name__ == "__main__":
    unittest.main()
