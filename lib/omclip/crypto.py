# SPDX-License-Identifier: MIT
"""Pure-python crypto / wire encodings for the Rapport companion-link protocol.

Developed against a standalone reference client (2026-10-13) and validated live
before being vendored here.

Nothing here is third-party: X25519 (RFC 7748), ChaCha20-Poly1305 (RFC 8439),
HKDF-SHA512 (RFC 5869), Ed25519 (RFC 8032) and the two Apple encodings
(TLV8, OPACK in pyatv's little-endian dialect).

One exception, added 2026-10-14: ChaCha20-Poly1305 is *also* available from the
system's OpenSSL libcrypto through ctypes, because pure-python AEAD costs
milliseconds of CPU per poll (~3.3 ms for the 412-byte request+response, the
largest single item in the loop). Only the AEAD primitive is taken from
libcrypto; everything else, and every failure/absent-library case, stays pure
python (`OMCLIP_CRYPTO=python` forces that path).
"""

import ctypes
import ctypes.util
import hashlib
import hmac
import os
import struct
import uuid

# --------------------------------------------------------------------------
# X25519 (RFC 7748)
# --------------------------------------------------------------------------

_P = 2 ** 255 - 19
_A24 = 121665


def _clamp(k):
    k = bytearray(k)
    k[0] &= 248
    k[31] &= 127
    k[31] |= 64
    return int.from_bytes(k, "little")


def x25519(private: bytes, peer_pub: bytes) -> bytes:
    k = _clamp(private)
    u = int.from_bytes(peer_pub, "little") & ((1 << 255) - 1)
    x1, x2, z2, x3, z3, swap = u, 1, 0, u, 1, 0
    for t in range(254, -1, -1):
        kt = (k >> t) & 1
        swap ^= kt
        if swap:
            x2, x3 = x3, x2
            z2, z3 = z3, z2
        swap = kt
        a = (x2 + z2) % _P
        aa = a * a % _P
        b = (x2 - z2) % _P
        bb = b * b % _P
        e = (aa - bb) % _P
        c = (x3 + z3) % _P
        d = (x3 - z3) % _P
        da = d * a % _P
        cb = c * b % _P
        x3 = (da + cb) % _P
        x3 = x3 * x3 % _P
        z3 = (da - cb) % _P
        z3 = z3 * z3 % _P
        z3 = z3 * x1 % _P
        x2 = aa * bb % _P
        z2 = e * (aa + _A24 * e) % _P
    if swap:
        x2, x3 = x3, x2
        z2, z3 = z3, z2
    return ((x2 * pow(z2, _P - 2, _P)) % _P).to_bytes(32, "little")


def x25519_base(private: bytes) -> bytes:
    return x25519(private, (9).to_bytes(32, "little"))


def new_ephemeral():
    """A fresh X25519 keypair. /dev/urandom via os.urandom (cross-platform)."""
    sk = os.urandom(32)
    return sk, x25519_base(sk)


# --------------------------------------------------------------------------
# ChaCha20-Poly1305 (RFC 8439)
#
# Two interchangeable backends, byte-identical on every input: the pure-python
# implementation below, and OpenSSL's libcrypto through ctypes (further down,
# used whenever it is loadable — see `aead_backend()`). `chacha20poly1305_*`
# are the only entry points; tests/test_crypto.py checks both against each
# other and against the RFC 8439 vector.
# --------------------------------------------------------------------------

def _rotl(v, n):
    return ((v << n) | (v >> (32 - n))) & 0xFFFFFFFF


def _chacha20_block(key, counter, nonce):
    x = list(struct.unpack("<4I", b"expand 32-byte k")) + \
        list(struct.unpack("<8I", key)) + [counter] + list(struct.unpack("<3I", nonce))
    work = x[:]
    for _ in range(10):
        for a, b, c, d in ((0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
                           (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14)):
            work[a] = (work[a] + work[b]) & 0xFFFFFFFF
            work[d] = _rotl(work[d] ^ work[a], 16)
            work[c] = (work[c] + work[d]) & 0xFFFFFFFF
            work[b] = _rotl(work[b] ^ work[c], 12)
            work[a] = (work[a] + work[b]) & 0xFFFFFFFF
            work[d] = _rotl(work[d] ^ work[a], 8)
            work[c] = (work[c] + work[d]) & 0xFFFFFFFF
            work[b] = _rotl(work[b] ^ work[c], 7)
    return struct.pack("<16I", *[(work[i] + x[i]) & 0xFFFFFFFF for i in range(16)])


def _chacha20_xor(key, counter, nonce, data):
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha20_block(key, counter + i // 64, nonce)
        chunk = data[i:i + 64]
        out += bytes(a ^ b for a, b in zip(chunk, ks))
    return bytes(out)


def _poly1305(msg, key):
    r = int.from_bytes(key[:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(key[16:32], "little")
    p = (1 << 130) - 5
    acc = 0
    for i in range(0, len(msg), 16):
        block = msg[i:i + 16]
        n = int.from_bytes(block, "little") + (1 << (8 * len(block)))
        acc = (acc + n) * r % p
    return ((acc + s) % (1 << 128)).to_bytes(16, "little")


def _chacha20poly1305_encrypt_python(key, nonce, plaintext, aad=b""):
    otk = _chacha20_block(key, 0, nonce)[:32]
    ct = _chacha20_xor(key, 1, nonce, plaintext)
    mac_data = aad + b"\x00" * (-len(aad) % 16) + ct + b"\x00" * (-len(ct) % 16)
    mac_data += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    return ct + _poly1305(mac_data, otk)


def _chacha20poly1305_decrypt_python(key, nonce, blob, aad=b""):
    ct, tag = blob[:-16], blob[-16:]
    otk = _chacha20_block(key, 0, nonce)[:32]
    mac_data = aad + b"\x00" * (-len(aad) % 16) + ct + b"\x00" * (-len(ct) % 16)
    mac_data += struct.pack("<Q", len(aad)) + struct.pack("<Q", len(ct))
    if not hmac.compare_digest(_poly1305(mac_data, otk), tag):
        raise ValueError("chacha20poly1305: bad tag")
    return _chacha20_xor(key, 1, nonce, ct)


# --------------------------------------------------------------------------
# The libcrypto backend (OpenSSL EVP_chacha20_poly1305, via ctypes)
#
# AES-free, no compiled code in the repo, no third-party package: just the
# libcrypto the machine already ships. Nothing here may ever reach a caller as
# anything but a correct AEAD result — a library that is missing, symbol-less or
# broken is a silent, permanent fall back to the pure-python code above.
# --------------------------------------------------------------------------

def _libcrypto_address(buf, offset=0):
    """A writable buffer as a plain address, for the c_void_p output parameters."""
    return ctypes.addressof(buf) + offset


class _LibcryptoError(RuntimeError):
    """Internal: libcrypto is unusable. Callers never see this — they get python."""


class _LibcryptoAEAD:
    """OpenSSL's EVP_chacha20_poly1305: 12-byte nonce, 16-byte tag appended to the ct.

    One-shot calls: a fresh EVP_CIPHER_CTX per operation, because an EVP context is
    stateful (reusing one across callers would be a locking question) and at 0.5
    polls/s the ~1 µs it costs to create and free one is not worth answering. AAD
    goes through the same update call as the payload, with a NULL output buffer (the
    documented way to feed AEAD associated data).
    """

    _SET_IVLEN = 0x9
    _GET_TAG = 0x10
    _SET_TAG = 0x11

    # Room for EVP_*Final_ex's output, which is its own buffer: EVP_chacha20_poly1305's
    # block size is 1, so Final must write nothing at all, and 32 bytes (OpenSSL's
    # EVP_MAX_BLOCK_LENGTH) means even a block cipher's padding would fit. Nothing
    # derived from a length OpenSSL reports is ever used as a write address.
    _TAIL_ROOM = 32

    # libcrypto symbol -> (attribute used below, restype, argtypes).
    _FUNCTIONS = {
        "EVP_chacha20_poly1305": ("_cipher", ctypes.c_void_p, ()),
        "EVP_CIPHER_CTX_new": ("_ctx_new", ctypes.c_void_p, ()),
        "EVP_CIPHER_CTX_free": ("_ctx_free", None, (ctypes.c_void_p,)),
        "EVP_CIPHER_CTX_ctrl": ("_ctrl", ctypes.c_int, (ctypes.c_void_p, ctypes.c_int,
                                                        ctypes.c_int, ctypes.c_void_p)),
        "EVP_EncryptInit_ex": ("_enc_in", ctypes.c_int, (ctypes.c_void_p, ctypes.c_void_p,
                                                         ctypes.c_void_p, ctypes.c_char_p,
                                                         ctypes.c_char_p)),
        "EVP_EncryptUpdate": ("_enc_update", ctypes.c_int, (ctypes.c_void_p, ctypes.c_void_p,
                                                            ctypes.POINTER(ctypes.c_int),
                                                            ctypes.c_char_p, ctypes.c_int)),
        "EVP_EncryptFinal_ex": ("_enc_final", ctypes.c_int, (ctypes.c_void_p, ctypes.c_void_p,
                                                             ctypes.POINTER(ctypes.c_int))),
        "EVP_DecryptInit_ex": ("_dec_in", ctypes.c_int, (ctypes.c_void_p, ctypes.c_void_p,
                                                         ctypes.c_void_p, ctypes.c_char_p,
                                                         ctypes.c_char_p)),
        "EVP_DecryptUpdate": ("_dec_update", ctypes.c_int, (ctypes.c_void_p, ctypes.c_void_p,
                                                            ctypes.POINTER(ctypes.c_int),
                                                            ctypes.c_char_p, ctypes.c_int)),
        "EVP_DecryptFinal_ex": ("_dec_final", ctypes.c_int, (ctypes.c_void_p, ctypes.c_void_p,
                                                             ctypes.POINTER(ctypes.c_int))),
    }

    def __init__(self, name):
        lib = ctypes.CDLL(name)
        for symbol, (attribute, restype, argtypes) in self._FUNCTIONS.items():
            try:
                func = getattr(lib, symbol)
            except AttributeError as exc:  # an OpenSSL without the AEAD
                raise _LibcryptoError(f"{name} has no {symbol}") from exc
            func.restype = restype
            func.argtypes = argtypes
            setattr(self, attribute, func)

    def _ctx(self):
        ctx = self._ctx_new()
        if not ctx:
            raise _LibcryptoError("EVP_CIPHER_CTX_new() returned NULL")
        return ctx

    def encrypt(self, key, nonce, plaintext, aad=b""):
        length = len(plaintext)
        buf = ctypes.create_string_buffer(length + 16)
        tailbuf = ctypes.create_string_buffer(self._TAIL_ROOM)
        written = ctypes.c_int(0)
        tail = ctypes.c_int(0)
        ctx = self._ctx()
        try:
            if not self._enc_in(ctx, self._cipher(), None, None, None):
                raise _LibcryptoError("EVP_EncryptInit_ex(cipher) failed")
            if not self._ctrl(ctx, self._SET_IVLEN, 12, None):
                raise _LibcryptoError("EVP_CTRL_AEAD_SET_IVLEN failed")
            if not self._enc_in(ctx, None, None, key, nonce):
                raise _LibcryptoError("EVP_EncryptInit_ex(key, iv) failed")
            if aad and not self._enc_update(ctx, None, ctypes.byref(written), aad, len(aad)):
                raise _LibcryptoError("EVP_EncryptUpdate(aad) failed")
            if not self._enc_update(ctx, _libcrypto_address(buf), ctypes.byref(written),
                                    plaintext, length):
                raise _LibcryptoError("EVP_EncryptUpdate failed")
            if written.value != length:      # checked before the tag's offset uses it
                raise _LibcryptoError("EVP_EncryptUpdate wrote %d bytes, expected %d"
                                      % (written.value, length))
            if not self._enc_final(ctx, _libcrypto_address(tailbuf), ctypes.byref(tail)):
                raise _LibcryptoError("EVP_EncryptFinal_ex failed")
            if tail.value:
                raise _LibcryptoError("EVP_EncryptFinal_ex wrote %d bytes" % tail.value)
            if not self._ctrl(ctx, self._GET_TAG, 16, _libcrypto_address(buf, length)):
                raise _LibcryptoError("EVP_CTRL_AEAD_GET_TAG failed")
        finally:
            self._ctx_free(ctx)
        raw = buf.raw
        return raw[:length] + raw[length:length + 16]

    def decrypt(self, key, nonce, blob, aad=b""):
        ciphertext, tag = blob[:-16], blob[-16:]
        if len(tag) != 16 or len(tag) != len(blob) - len(ciphertext):
            raise ValueError("chacha20poly1305: bad tag")
        length = len(ciphertext)
        buf = ctypes.create_string_buffer(length + 16)
        tailbuf = ctypes.create_string_buffer(self._TAIL_ROOM)
        tagbuf = ctypes.create_string_buffer(tag)
        written = ctypes.c_int(0)
        tail = ctypes.c_int(0)
        ctx = self._ctx()
        try:
            if not self._dec_in(ctx, self._cipher(), None, None, None):
                raise _LibcryptoError("EVP_DecryptInit_ex(cipher) failed")
            if not self._ctrl(ctx, self._SET_IVLEN, 12, None):
                raise _LibcryptoError("EVP_CTRL_AEAD_SET_IVLEN failed")
            if not self._dec_in(ctx, None, None, key, nonce):
                raise _LibcryptoError("EVP_DecryptInit_ex(key, iv) failed")
            if aad and not self._dec_update(ctx, None, ctypes.byref(written), aad, len(aad)):
                raise _LibcryptoError("EVP_DecryptUpdate(aad) failed")
            if not self._dec_update(ctx, _libcrypto_address(buf), ctypes.byref(written),
                                    ciphertext, length):
                raise _LibcryptoError("EVP_DecryptUpdate failed")
            if written.value != length:      # checked before Final's offset uses it
                raise _LibcryptoError("EVP_DecryptUpdate wrote %d bytes, expected %d"
                                      % (written.value, length))
            if not self._ctrl(ctx, self._SET_TAG, 16, ctypes.addressof(tagbuf)):
                raise _LibcryptoError("EVP_CTRL_AEAD_SET_TAG failed")
            if not self._dec_final(ctx, _libcrypto_address(tailbuf), ctypes.byref(tail)):
                raise ValueError("chacha20poly1305: bad tag")
            if tail.value:
                raise _LibcryptoError("EVP_DecryptFinal_ex wrote %d bytes" % tail.value)
        finally:
            self._ctx_free(ctx)
        return buf.raw[:length]


# Why libcrypto is not in use, when it isn't: the override as it was set
# ("disabled by OMCLIP_CRYPTO='py'"), a missing library, a missing symbol, a
# call-time failure. None while healthy.
_LIBCRYPTO_ERROR = None


def _degrade(where, exc):
    """Give up on libcrypto for good; the pure-python path takes over silently."""
    global _libcrypto, _LIBCRYPTO_ERROR
    _libcrypto = None
    _LIBCRYPTO_ERROR = f"{where}: {type(exc).__name__}: {exc}"


def _load_libcrypto():
    """The libcrypto backend, or None (reason recorded in _LIBCRYPTO_ERROR)."""
    global _LIBCRYPTO_ERROR
    value = os.environ.get("OMCLIP_CRYPTO")
    if value is not None and value.strip().lower() in ("python", "py", "pure"):
        # Name the value as it was set, so the diagnostic cannot contradict the
        # environment ("OMCLIP_CRYPTO=py" reads differently from "=python").
        _LIBCRYPTO_ERROR = "disabled by OMCLIP_CRYPTO=%r" % (value,)
        return None
    _LIBCRYPTO_ERROR = None          # no override: the load below decides the reason
    try:
        name = ctypes.util.find_library("crypto")
        if not name:
            raise _LibcryptoError("ctypes.util.find_library('crypto') found nothing")
        return _LibcryptoAEAD(name)
    except Exception as exc:  # no libcrypto, no symbol, no libdl: all fine, just python
        _LIBCRYPTO_ERROR = f"{type(exc).__name__}: {exc}"
        return None


_libcrypto = _load_libcrypto()


def aead_backend():
    """Which ChaCha20-Poly1305 implementation is live: 'libcrypto' or 'python'."""
    return "libcrypto" if _libcrypto is not None else "python"


def aead_detail():
    """Why the pure-python implementation is in use, or None while libcrypto is live.

    The public face of `_LIBCRYPTO_ERROR`: `status.health.crypto_detail` and `omclip
    doctor` report it, so a silent fall back is never actually silent.
    """
    return _LIBCRYPTO_ERROR


def chacha20poly1305_encrypt(key, nonce, plaintext, aad=b""):
    # The pre-checks below are the shape libcrypto needs (32-byte key, 12-byte
    # nonce, real bytes). Anything else — and any libcrypto failure — goes to the
    # pure-python path, which accepts what it always accepted and throws what it
    # always threw, rather than handing OpenSSL a length it would over-read.
    if (_libcrypto is not None
            and type(key) is bytes and len(key) == 32
            and type(nonce) is bytes and len(nonce) == 12
            and type(plaintext) is bytes and type(aad) is bytes):
        try:
            return _libcrypto.encrypt(key, nonce, plaintext, aad)
        except ValueError:
            raise
        except Exception as exc:
            _degrade("encrypt", exc)
    return _chacha20poly1305_encrypt_python(key, nonce, plaintext, aad)


def chacha20poly1305_decrypt(key, nonce, blob, aad=b""):
    if (_libcrypto is not None
            and type(key) is bytes and len(key) == 32
            and type(nonce) is bytes and len(nonce) == 12
            and type(blob) is bytes and len(blob) >= 16 and type(aad) is bytes):
        try:
            return _libcrypto.decrypt(key, nonce, blob, aad)
        except ValueError:
            raise
        except Exception as exc:
            _degrade("decrypt", exc)
    return _chacha20poly1305_decrypt_python(key, nonce, blob, aad)


# --------------------------------------------------------------------------
# HKDF-SHA512 / Ed25519
# --------------------------------------------------------------------------

def hkdf_sha512(ikm, salt, info, length=32):
    prk = hmac.new(salt, ikm, hashlib.sha512).digest()
    okm, t = b"", b""
    for i in range(1, (length + 63) // 64 + 1):
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha512).digest()
        okm += t
    return okm[:length]


def ed25519_sign(sk: bytes, msg: bytes) -> bytes:
    """Pure-python Ed25519 sign (RFC 8032). sk = 32-byte seed."""
    q = 2 ** 255 - 19
    l = 2 ** 252 + 27742317777372353535851937790883648493
    d = -121665 * pow(121666, q - 2, q) % q
    i = pow(2, (q - 1) // 4, q)

    def x_recover(y):
        xx = (y * y - 1) * pow(d * y * y + 1, q - 2, q)
        x = pow(xx, (q + 3) // 8, q)
        if (x * x - xx) % q != 0:
            x = x * i % q
        if x % 2 != 0:
            x = q - x
        return x

    by = 4 * pow(5, q - 2, q) % q
    bx = x_recover(by)
    b = (bx, by, 1, bx * by % q)

    def edwards_add(p, r):
        x1, y1, z1, t1 = p
        x2, y2, z2, t2 = r
        a = (y1 - x1) * (y2 - x2) % q
        bb = (y1 + x1) * (y2 + x2) % q
        c = t1 * 2 * d * t2 % q
        dd = z1 * 2 * z2 % q
        e, f, g, h = bb - a, dd - c, dd + c, bb + a
        return (e * f % q, g * h % q, f * g % q, e * h % q)

    def scalarmult(p, n):
        res = (0, 1, 1, 0)
        while n:
            if n & 1:
                res = edwards_add(res, p)
            p = edwards_add(p, p)
            n >>= 1
        return res

    def encodepoint(p):
        x, y, z, _ = p
        zi = pow(z, q - 2, q)
        return ((y * zi % q) | ((x * zi % q & 1) << 255)).to_bytes(32, "little")

    h = hashlib.sha512(sk).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    prefix = h[32:]
    A = encodepoint(scalarmult(b, a))
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % l
    R = encodepoint(scalarmult(b, r))
    k = int.from_bytes(hashlib.sha512(R + A + msg).digest(), "little") % l
    s = (r + k * a) % l
    return R + s.to_bytes(32, "little")


# --------------------------------------------------------------------------
# TLV8 (Apple's 255-byte-chunked tag/length/value)
# --------------------------------------------------------------------------

def tlv8_encode(items):
    out = bytearray()
    for tag, value in items:
        for i in range(0, max(len(value), 1), 255):
            chunk = value[i:i + 255]
            out += bytes([tag, len(chunk)]) + chunk
            if i + 255 >= len(value):
                break
    return bytes(out)


def tlv8_decode(data):
    """Concatenating decoder: a tag split over chunks reads back as one value.

    (Pair-Verify M1/M2 always fit in one chunk, but the reference client
    concatenates and so do we — the same bytes must decode identically.)
    """
    out, i = {}, 0
    while i + 1 < len(data):
        tag, ln = data[i], data[i + 1]
        out.setdefault(tag, b"")
        out[tag] += data[i + 2:i + 2 + ln]
        i += 2 + ln
    return out


# --------------------------------------------------------------------------
# OPACK (pyatv dialect: little-endian, shared object table)
# Based on pyatv support/opack.py — Copyright (c) Pierre Ståhl (MIT License)
# --------------------------------------------------------------------------

def opack_encode(obj):
    """OPACK encoder, byte-compatible with pyatv's support/opack.py.

    Little-endian scalars; dict/list markers carry min(count, 0xF) in the low
    nibble, and count >= 0xF uses the *endless* form terminated by 0x03.
    """
    out = bytearray()

    def enc(o):
        if o is None:
            out.append(0x04)
        elif o is True:
            out.append(0x01)
        elif o is False:
            out.append(0x02)
        elif isinstance(o, int):
            if 0 <= o < 0x28:
                out.append(o + 8)
            elif o <= 0xFF:
                out.extend(bytes([0x30]) + o.to_bytes(1, "little"))
            elif o <= 0xFFFF:
                out.extend(bytes([0x31]) + o.to_bytes(2, "little"))
            elif o <= 0xFFFFFFFF:
                out.extend(bytes([0x32]) + o.to_bytes(4, "little"))
            else:
                out.extend(bytes([0x33]) + o.to_bytes(8, "little"))
        elif isinstance(o, bytes):
            n = len(o)
            if n <= 0x20:
                out.append(0x70 + n)
            elif n <= 0xFF:
                out.extend(bytes([0x91, n]))
            elif n <= 0xFFFF:
                out.extend(bytes([0x92]) + n.to_bytes(2, "little"))
            else:
                out.extend(bytes([0x93]) + n.to_bytes(4, "little"))
            out.extend(o)
        elif isinstance(o, str):
            b = o.encode()
            n = len(b)
            if n <= 0x20:
                out.append(0x40 + n)
            elif n <= 0xFF:
                out.extend(bytes([0x61, n]))
            elif n <= 0xFFFF:
                out.extend(bytes([0x62]) + n.to_bytes(2, "little"))
            else:
                out.extend(bytes([0x63]) + n.to_bytes(3, "little"))
            out.extend(b)
        elif isinstance(o, (list, tuple)):
            out.append(0xD0 + min(len(o), 0xF))
            for x in o:
                enc(x)
            if len(o) >= 0xF:
                out.append(0x03)
        elif isinstance(o, dict):
            out.append(0xE0 + min(len(o), 0xF))
            for k, v in o.items():
                enc(k)
                enc(v)
            if len(o) >= 0xF:
                out.append(0x03)
        else:
            raise TypeError(type(o))

    enc(obj)
    return bytes(out)


def opack_decode(data, object_list=None):
    """OPACK decoder (pyatv semantics, including the object-reference table).

    Markers: small ints 0x08|n; sized ints 0x30-0x33; strings 0x40|len and
    0x61-0x64 + len; data 0x70|len and 0x91-0x94 + len; lists 0xD0|count;
    dicts 0xE0|count (count 0xF = endless, terminated by 0x03); a value already
    seen once is emitted as a reference 0xA0|index (< 0x21) or 0xC1-0xC4 +
    index, indexing the same ordered table `pack` builds (every value whose
    packed form is longer than one byte, first occurrence only). Returns
    (value, trailing_byte_count).
    """
    pos = 0
    objs = [] if object_list is None else object_list

    def read(n):
        nonlocal pos
        out = data[pos:pos + n]
        pos += n
        return out

    def value():
        nonlocal pos
        start = pos
        t = read(1)[0]
        v = None
        if t == 0x01:
            v = True
        elif t == 0x02:
            v = False
        elif t == 0x04:
            v = None
        elif t == 0x05:
            v = uuid.UUID(bytes=read(16))
        elif t == 0x06:
            v = int.from_bytes(read(8), "little")
        elif 0x08 <= t <= 0x2F:
            v = t - 0x08
        elif t == 0x35:
            v = struct.unpack("<f", read(4))[0]
        elif t == 0x36:
            v = struct.unpack("<d", read(8))[0]
        elif 0x30 <= t <= 0x33:
            v = int.from_bytes(read(2 ** (t & 0x0F)), "little")
        elif 0x40 <= t <= 0x60:
            v = read(t - 0x40).decode("utf-8", "replace")
        elif 0x61 <= t <= 0x64:
            n = int.from_bytes(read(t & 0x0F), "little")
            v = read(n).decode("utf-8", "replace")
        elif 0x70 <= t <= 0x90:
            v = read(t - 0x70)
        elif 0x91 <= t <= 0x94:
            n = int.from_bytes(read(1 << ((t & 0x0F) - 1)), "little")
            v = read(n)
        elif 0xA0 <= t <= 0xC0:
            idx = t - 0xA0
            return objs[idx] if idx < len(objs) else "<objref %d>" % idx
        elif 0xC1 <= t <= 0xC4:
            idx = int.from_bytes(read(t - 0xC0), "little")
            return objs[idx] if idx < len(objs) else "<objref %d>" % idx
        elif (t & 0xF0) == 0xD0:
            count = t & 0x0F
            v = []
            if count == 0x0F:
                while pos < len(data) and data[pos] != 0x03:
                    v.append(value())
                pos += 1
            else:
                for _ in range(count):
                    v.append(value())
        elif (t & 0xF0) == 0xE0:
            count = t & 0x0F
            v = {}
            if count == 0x0F:
                while pos < len(data) and data[pos] != 0x03:
                    k = value()
                    v[k if isinstance(k, (str, int)) else str(k)] = value()
                pos += 1
            else:
                for _ in range(count):
                    k = value()
                    v[k if isinstance(k, (str, int)) else str(k)] = value()
        else:
            raise ValueError("opack: unknown type 0x%02x at %d" % (t, pos - 1))
        if pos - start > 1 and v not in objs:
            objs.append(v)
        return v

    obj = value()
    return obj, len(data) - pos
