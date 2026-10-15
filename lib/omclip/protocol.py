"""Rapport / CompanionLink wire protocol: framing, Pair-Verify, content channel.

Developed against a standalone reference client and validated live against
macOS 27 `rapportd` and iOS 18 on 2026-10-13.

Measured facts this file encodes:

* Pair-Verify M1 MUST carry the `0x19` AppFlags=1 TLV. With it the peer takes the
  same-account RPIdentity path, M2 carries no identifier, M3 is signature-only
  (`sign(client_eph_pub ‖ server_eph_pub)`) and no identifier is needed at all.
* Keys: HKDF-SHA512(shared, "Pair-Verify-Encrypt-Salt", "Pair-Verify-Encrypt-Info").
* The content channel is frame type 8 (`E_OPACK`), sealed with
  HKDF-SHA512(shared, "", "ClientEncrypt-main"/"ServerEncrypt-main"), a 12-byte
  little-endian counter nonce, and the 4-byte frame header as AAD.
* `_systemInfo` carrying our `_idsID` is a hard precondition for every
  `com.apple.handoff.payload-request`: without it the peer answers
  `{_ec: 58828, _em: "IDS device not found"}`.
"""

import hashlib
import socket
import struct
import time

from .crypto import (chacha20poly1305_decrypt, chacha20poly1305_encrypt, hkdf_sha512,
                     new_ephemeral, opack_decode, opack_encode, tlv8_decode, tlv8_encode,
                     x25519)

FRAME_M1 = 5
FRAME_PV = 6
FRAME_OPACK = 8

SALT = b"Pair-Verify-Encrypt-Salt"
INFO = b"Pair-Verify-Encrypt-Info"

#: The pasteboard announcement body the peer echoes back in `rAdvPayload`
#: (2019 Handoff-Swift capture). Any value is accepted once `_idsID` resolves —
#: replayed genuine phone payloads change nothing, so this constant is fine.
HANDOFF_ADV_PAYLOAD = bytes.fromhex("a1072cb8bf1d9818ac")


class PeerError(Exception):
    """Any failure attributable to a peer session."""


class PeerGone(PeerError):
    """The peer closed the connection (rapportd evicts a second session)."""


class RequestTimeout(PeerError):
    """No matching response inside the request deadline."""


class AuthFailed(PeerError):
    """Pair-Verify did not reach M4 success."""


class StopRequested(Exception):
    """Cooperative shutdown signal raised inside a bounded wait."""


# --------------------------------------------------------------------------
# framing
# --------------------------------------------------------------------------

def frame(frame_type, body):
    return struct.pack(">B", frame_type) + len(body).to_bytes(3, "big") + body


def recv_frame(sock):
    header = b""
    while len(header) < 4:
        chunk = sock.recv(4 - len(header))
        if not chunk:
            raise PeerGone("connection closed")
        header += chunk
    ft = header[0]
    ln = int.from_bytes(header[1:4], "big")
    body = b""
    while len(body) < ln:
        chunk = sock.recv(ln - len(body))
        if not chunk:
            raise PeerGone("connection closed mid-body")
        body += chunk
    return ft, body


class ContentChannel:
    """ChaCha20-Poly1305 sealed OPACK frames, as CompanionLink uses after M4."""

    def __init__(self, shared: bytes, client_role=True):
        server = hkdf_sha512(shared, b"", b"ServerEncrypt-main", 32)
        client = hkdf_sha512(shared, b"", b"ClientEncrypt-main", 32)
        self.enc_key, self.dec_key = (client, server) if client_role else (server, client)
        self.enc_n = 0
        self.dec_n = 0

    @staticmethod
    def _nonce(n):
        return n.to_bytes(12, "little")

    def seal(self, plaintext: bytes, aad: bytes = b"") -> bytes:
        out = chacha20poly1305_encrypt(self.enc_key, self._nonce(self.enc_n), plaintext, aad)
        self.enc_n += 1
        return out

    def open(self, ciphertext: bytes, aad: bytes = b"") -> bytes:
        out = chacha20poly1305_decrypt(self.dec_key, self._nonce(self.dec_n), ciphertext, aad)
        self.dec_n += 1
        return out


def send_frame(sock, frame_type, body, channel=None):
    if channel is not None and body:
        header = bytes([frame_type]) + (len(body) + 16).to_bytes(3, "big")
        sock.sendall(header + channel.seal(body, aad=header))
    else:
        sock.sendall(bytes([frame_type]) + len(body).to_bytes(3, "big") + body)


def recv_frame_decrypted(sock, channel):
    """(frame_type, object_or_bytes). The counter is only advanced on success."""
    ft, body = recv_frame(sock)
    if channel is None or not body:
        return ft, body
    aad = bytes([ft]) + len(body).to_bytes(3, "big")
    return ft, opack_decode(channel.open(body, aad=aad))[0]


# --------------------------------------------------------------------------
# Pair-Verify
# --------------------------------------------------------------------------

def nonce(msg):
    return b"\x00" * (12 - len(msg)) + msg


def _pv_m1(eph_pub):
    """The only M1 encoding that authenticates: `_pd` TLV {3: pub, 6: 1, 19: 1}."""
    body = opack_encode({"_pd": tlv8_encode([(0x03, eph_pub), (0x06, b"\x01"),
                                             (0x19, b"\x01")])})
    return frame(FRAME_M1, body)


def _pv_m3(key, ed_sk, client_pub, server_pub):
    """Signature-only M3 (RPIdentity path): TLV {5: enc(TLV{10: sig})}."""
    inner = tlv8_encode([(0x0A, _ed_sign(ed_sk, client_pub + server_pub))])
    enc = chacha20poly1305_encrypt(key, nonce(b"PV-Msg03"), inner)
    return frame(FRAME_PV, opack_encode({"_pd": tlv8_encode([(0x06, b"\x03"), (0x05, enc)])}))


def _ed_sign(ed_sk, msg):
    # Imported lazily to keep the module namespace tidy for tests that patch it.
    from .crypto import ed25519_sign
    return ed25519_sign(ed_sk, msg)


def pair_verify(sock, ed_sk, timeout=5.0):
    """Run M1→M4 on an open socket. Returns the shared secret; raises otherwise.

    Total bounded time: `timeout` (the socket timeout) bounds each read, and the
    handshake is exactly four messages, so worst case ~2× timeout.
    """
    eph_sk, eph_pub = new_ephemeral()
    sock.sendall(_pv_m1(eph_pub))
    ft, body = recv_frame(sock)
    obj, _ = opack_decode(body)
    tlv = tlv8_decode(obj.get("_pd", b""))
    if 0x03 not in tlv or 0x05 not in tlv:
        raise AuthFailed("M2 missing TLV 3/5 (frame %d)" % ft)
    peer_pub = tlv[0x03]
    key = hkdf_sha512(x25519(eph_sk, peer_pub), SALT, INFO, 32)
    proof = chacha20poly1305_decrypt(key, nonce(b"PV-Msg02"), tlv[0x05])
    ptlv = tlv8_decode(proof)
    if 0x0A not in ptlv:
        raise AuthFailed("M2 proof has no signature")
    sock.sendall(_pv_m3(key, ed_sk, eph_pub, peer_pub))
    ft4, body4 = recv_frame(sock)
    m4 = tlv8_decode(opack_decode(body4)[0].get("_pd", b""))
    if 0x07 in m4:
        raise AuthFailed("M4 error 0x%02x" % m4[0x07][0])
    if b"\x04" not in m4.get(0x06, b""):
        raise AuthFailed("unexpected M4 %s" % {hex(k): v.hex() for k, v in m4.items()})
    shared = x25519(eph_sk, peer_pub)
    return shared


def connect(host, port, timeout=5.0, iface=None):
    """TCP connect with a hard deadline and keepalive on.

    Link-local (`fe80::…`) peers need the interface scope; `getaddrinfo` takes
    the `%iface` suffix natively on Linux.
    """
    name = "%s%%%s" % (host, iface) if (iface and "%" not in host) else host
    infos = socket.getaddrinfo(name, port, 0, socket.SOCK_STREAM)
    if not infos:
        raise PeerError("no address for %s:%s" % (host, port))
    af, st, proto, _, addr = infos[0]
    s = socket.socket(af, st, proto)
    s.settimeout(timeout)
    # rapportd treats a dead connection as an occupied session slot; let the
    # kernel reap it instead of waiting out a 30 s idle timeout.
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    except OSError:
        pass
    try:
        s.connect(addr)
    except Exception:
        s.close()
        raise
    return s


# --------------------------------------------------------------------------
# `_systemInfo`
# --------------------------------------------------------------------------

DEFAULT_MODEL = "MacBookAir6,2"


def build_system_info(ids_id="", name=None, model=DEFAULT_MODEL, dev_id=None, pub_id="",
                      sv="715.2"):
    """Our `_systemInfo`. `_idsID` is load-bearing (see module docstring)."""
    return {
        "_bf": 0, "_cf": 512, "_clFl": 128,
        "_i": dev_id or "2a8479299665",
        "_idsID": ids_id, "_pubID": pub_id, "_sf": 256, "_sv": sv,
        "model": model, "name": name or socket.gethostname(),
    }


def device_info_id(ed_pk_hex):
    """Stable 12-hex-char `_i` derived from our long-term identity (reference formula)."""
    return hashlib.md5(("rapport-device-info:" + ed_pk_hex).encode()).hexdigest()[:12]


def announce_system_info(sock, channel, ids_id, ed_pk_hex, name=None,
                         model=DEFAULT_MODEL, xid=1):
    info = build_system_info(ids_id, name=name, model=model,
                             dev_id=device_info_id(ed_pk_hex))
    send_frame(sock, FRAME_OPACK,
               opack_encode({"_i": "_systemInfo", "_t": 2, "_x": xid, "_c": info}),
               channel)


# --------------------------------------------------------------------------
# payload requests
# --------------------------------------------------------------------------

def payload_request_body(command, adv=HANDOFF_ADV_PAYLOAD, xid=2):
    """`com.apple.handoff.payload-request`. `pbtypes` = metadata only, `pbpaste2` = content."""
    return opack_encode({"_i": "com.apple.handoff.payload-request", "_t": 2, "_x": xid,
                         "_c": {"rAdvPayload": adv, "rClientCommand": command,
                                "rIdentifier": ""}})


def now():
    return time.monotonic()
