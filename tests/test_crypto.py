"""The vendored crypto/encodings, pinned to vectors.

The X25519, ChaCha20-Poly1305, HKDF, Ed25519 and OPACK/TLV8 vectors were produced with
the standalone reference client these primitives were vendored from — so a drift from
it (or from the RFCs for X25519 and ChaCha20-Poly1305) fails loudly here instead of on
the wire.

ChaCha20-Poly1305 has two interchangeable backends since 2026-10-14 (the system
libcrypto through ctypes, and the pure-python code): both are pinned to the RFC 8439
vector and to each other on random input, and the whole module is run a second time in
a child interpreter with `OMCLIP_CRYPTO=python` (see ForcedPurePython).
"""

import contextlib
import ctypes.util
import os
import random
import struct
import subprocess
import sys
import unittest
import unittest.mock

import _support  # noqa: F401  (path setup)
from omclip import crypto


class X25519(unittest.TestCase):
    # RFC 7748 §6.1
    ALICE_SK = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    ALICE_PK = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    BOB_SK = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    BOB_PK = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    SHARED = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

    def test_base_points(self):
        self.assertEqual(crypto.x25519_base(self.ALICE_SK).hex(), self.ALICE_PK)
        self.assertEqual(crypto.x25519_base(self.BOB_SK).hex(), self.BOB_PK)

    def test_shared_secret_matches_both_sides(self):
        alice = crypto.x25519(self.ALICE_SK, bytes.fromhex(self.BOB_PK))
        bob = crypto.x25519(self.BOB_SK, bytes.fromhex(self.ALICE_PK))
        self.assertEqual(alice.hex(), self.SHARED)
        self.assertEqual(alice, bob)

    def test_ephemeral_is_random(self):
        first = crypto.new_ephemeral()
        second = crypto.new_ephemeral()
        self.assertEqual(len(first[0]), 32)
        self.assertEqual(len(first[1]), 32)
        self.assertNotEqual(first[0], second[0])


class ChaCha20Poly1305(unittest.TestCase):
    # RFC 8439 §2.8.2
    KEY = bytes.fromhex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    NONCE = bytes.fromhex("070000004041424344454647")
    AAD = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    PLAIN = (b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip "
             b"for the future, sunscreen would be it.")
    EXPECTED = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b61161ae10b594f09e26a7e902ecbd0600691")

    def test_rfc_vector(self):
        self.assertEqual(crypto.chacha20poly1305_encrypt(self.KEY, self.NONCE, self.PLAIN,
                                                         self.AAD), self.EXPECTED)

    def test_roundtrip(self):
        blob = crypto.chacha20poly1305_encrypt(self.KEY, b"\x00" * 12, b"hello", b"aad")
        self.assertEqual(crypto.chacha20poly1305_decrypt(self.KEY, b"\x00" * 12, blob, b"aad"),
                         b"hello")

    def test_tampered_tag_is_rejected(self):
        blob = bytearray(crypto.chacha20poly1305_encrypt(self.KEY, b"\x00" * 12, b"hello"))
        blob[-1] ^= 0x01
        with self.assertRaises(ValueError):
            crypto.chacha20poly1305_decrypt(self.KEY, b"\x00" * 12, bytes(blob))

    def test_wrong_aad_is_rejected(self):
        blob = crypto.chacha20poly1305_encrypt(self.KEY, b"\x00" * 12, b"hello", b"aad")
        with self.assertRaises(ValueError):
            crypto.chacha20poly1305_decrypt(self.KEY, b"\x00" * 12, blob, b"other")


LIBCRYPTO = crypto.aead_backend() == "libcrypto"
NO_LIBCRYPTO = "this machine has no usable libcrypto (OMCLIP_CRYPTO=python or no OpenSSL)"
FORCING_PYTHON = ("python", "py", "pure")


def _forced_pure_python():
    return os.environ.get("OMCLIP_CRYPTO", "").strip().lower() in FORCING_PYTHON


@contextlib.contextmanager
def _no_override():
    """`_load_libcrypto()` as it behaves with no OMCLIP_CRYPTO in the environment.

    `_load_libcrypto()` writes the module globals, so they are put back afterwards:
    the rest of the module asserts the live backend.
    """
    with unittest.mock.patch.dict(os.environ), \
            unittest.mock.patch.object(crypto, "_libcrypto", crypto._libcrypto), \
            unittest.mock.patch.object(crypto, "_LIBCRYPTO_ERROR", crypto._LIBCRYPTO_ERROR):
        os.environ.pop("OMCLIP_CRYPTO", None)
        yield


class _BrokenBackend:
    """Loads fine, fails at call time — the daemon must survive exactly this."""

    def encrypt(self, key, nonce, plaintext, aad=b""):
        raise OSError("libcrypto went away")

    def decrypt(self, key, nonce, blob, aad=b""):
        raise OSError("libcrypto went away")


class ChaCha20Poly1305Backends(unittest.TestCase):
    """libcrypto (the daemon's default) and pure python, byte for byte.

    Parity alone would also pass if libcrypto silently fell back, so the active
    backend is asserted too, and the RFC 8439 vector is checked through each
    backend's own entry point.
    """

    #: The daemon's request body (/2 poll): 412 bytes, sealed with the frame header as AAD.
    REQUEST = bytes(i % 251 for i in range(412))
    REQUEST_AAD = b"\x02" + (412 + 16).to_bytes(3, "big")
    #: And a large clipboard item, the size the benchmark's other case uses.
    BULK = bytes(i % 251 for i in range(64 * 1024))

    def test_the_backend_here_is_the_one_the_environment_asked_for(self):
        if _forced_pure_python():
            self.assertEqual(crypto.aead_backend(), "python")
            self.assertIn("OMCLIP_CRYPTO", crypto._LIBCRYPTO_ERROR or "")
        else:
            # OpenSSL 3 is on this machine, so the fast path must be the live one.
            # If this fails, crypto._LIBCRYPTO_ERROR says why — and the daemon is
            # quietly back to pure-python AEAD.
            self.assertEqual(crypto.aead_backend(), "libcrypto", crypto._LIBCRYPTO_ERROR)
            self.assertIsNone(crypto._LIBCRYPTO_ERROR)

    def test_python_backend_matches_the_rfc_vector(self):
        self.assertEqual(
            crypto._chacha20poly1305_encrypt_python(
                ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                ChaCha20Poly1305.PLAIN, ChaCha20Poly1305.AAD),
            ChaCha20Poly1305.EXPECTED)
        self.assertEqual(
            crypto._chacha20poly1305_decrypt_python(
                ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                ChaCha20Poly1305.EXPECTED, ChaCha20Poly1305.AAD),
            ChaCha20Poly1305.PLAIN)

    @unittest.skipUnless(LIBCRYPTO, NO_LIBCRYPTO)
    def test_libcrypto_backend_matches_the_rfc_vector(self):
        self.assertEqual(
            crypto._libcrypto.encrypt(ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                                      ChaCha20Poly1305.PLAIN, ChaCha20Poly1305.AAD),
            ChaCha20Poly1305.EXPECTED)
        self.assertEqual(
            crypto._libcrypto.decrypt(ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                                      ChaCha20Poly1305.EXPECTED, ChaCha20Poly1305.AAD),
            ChaCha20Poly1305.PLAIN)
        self.assertIsNone(crypto._LIBCRYPTO_ERROR)

    @unittest.skipUnless(LIBCRYPTO, NO_LIBCRYPTO)
    def test_random_inputs_agree_across_backends(self):
        rng = random.Random(20261014)
        sizes = [0, 1, 15, 16, 17, 63, 64, 65, 100, 412, 1024, 4096]
        for case in range(120):
            key, nonce = rng.randbytes(32), rng.randbytes(12)
            plain = rng.randbytes(rng.choice(sizes))
            aad = rng.randbytes(rng.choice([0, 1, 16, 17, 64]))
            expected = crypto._chacha20poly1305_encrypt_python(key, nonce, plain, aad)
            fast = crypto.chacha20poly1305_encrypt(key, nonce, plain, aad)
            self.assertEqual(fast, expected, "case %d: %d bytes, %d aad" % (case, len(plain),
                                                                           len(aad)))
            self.assertEqual(crypto.chacha20poly1305_decrypt(key, nonce, expected, aad), plain)
            self.assertEqual(crypto._chacha20poly1305_decrypt_python(key, nonce, fast, aad),
                             plain)
        self.assertEqual(crypto.aead_backend(), "libcrypto", crypto._LIBCRYPTO_ERROR)

    def test_the_daemon_payload_shapes_agree_across_backends(self):
        for label, payload, aad in (
                ("412 B request, frame header AAD", self.REQUEST, self.REQUEST_AAD),
                ("412 B request, no AAD", self.REQUEST, b""),
                ("64 KiB payload", self.BULK, b"")):
            expected = crypto._chacha20poly1305_encrypt_python(
                ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE, payload, aad)
            self.assertEqual(
                crypto.chacha20poly1305_encrypt(ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                                                payload, aad),
                expected, label)
            self.assertEqual(
                crypto.chacha20poly1305_decrypt(ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                                                expected, aad),
                payload, label)

    @unittest.skipUnless(LIBCRYPTO, NO_LIBCRYPTO)
    def test_libcrypto_rejects_a_tampered_tag_or_ciphertext(self):
        for offset in (-1, 0):
            blob = bytearray(crypto.chacha20poly1305_encrypt(
                ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE, self.REQUEST, self.REQUEST_AAD))
            blob[offset] ^= 0x01
            with self.assertRaises(ValueError):
                crypto.chacha20poly1305_decrypt(ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                                                bytes(blob), self.REQUEST_AAD)
        with self.assertRaises(ValueError):     # wrong AAD, right tag
            crypto.chacha20poly1305_decrypt(ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                                            self.REQUEST, b"")
        self.assertEqual(crypto.aead_backend(), "libcrypto", crypto._LIBCRYPTO_ERROR)

    def test_a_libcrypto_that_fails_at_call_time_degrades_and_still_works(self):
        with unittest.mock.patch.object(crypto, "_libcrypto", _BrokenBackend()), \
                unittest.mock.patch.object(crypto, "_LIBCRYPTO_ERROR", None):
            self.assertEqual(
                crypto.chacha20poly1305_encrypt(ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE,
                                                ChaCha20Poly1305.PLAIN, ChaCha20Poly1305.AAD),
                ChaCha20Poly1305.EXPECTED)
            self.assertIsNone(crypto._libcrypto)
            self.assertIn("OSError", crypto._LIBCRYPTO_ERROR)
            self.assertEqual(crypto.aead_backend(), "python")
            self.assertEqual(crypto.chacha20poly1305_decrypt(
                ChaCha20Poly1305.KEY, ChaCha20Poly1305.NONCE, ChaCha20Poly1305.EXPECTED,
                ChaCha20Poly1305.AAD), ChaCha20Poly1305.PLAIN)
            self.assertEqual(crypto._LIBCRYPTO_ERROR.count("OSError"), 1)

    def test_the_override_diagnostic_echoes_the_value_that_was_set(self):
        # The reason has to name the environment as it actually is, not a canonical
        # spelling of it, or the diagnostic contradicts `env` while debugging.
        for raw in ("python", "py", "pure", "PYTHON", " py "):
            with _no_override(), unittest.mock.patch.dict(os.environ,
                                                          {"OMCLIP_CRYPTO": raw}):
                self.assertIsNone(crypto._load_libcrypto())
                self.assertEqual(crypto._LIBCRYPTO_ERROR,
                                 "disabled by OMCLIP_CRYPTO=%r" % (raw,))
        with _no_override(), unittest.mock.patch.dict(os.environ, {"OMCLIP_CRYPTO": "yes"}):
            crypto._load_libcrypto()          # 'yes' is not one of the accepted values
            self.assertNotIn("OMCLIP_CRYPTO", crypto._LIBCRYPTO_ERROR or "")

    def test_a_missing_library_is_a_silent_fallback(self):
        with _no_override():
            with unittest.mock.patch.object(crypto.ctypes.util, "find_library",
                                            return_value=None):
                self.assertIsNone(crypto._load_libcrypto())
                self.assertIn("find_library", crypto._LIBCRYPTO_ERROR)

    def test_a_library_without_the_aead_symbol_is_a_silent_fallback(self):
        other = ctypes.util.find_library("m")
        if not other:
            self.skipTest("no libm to stand in for an OpenSSL without the AEAD")
        with _no_override():
            with unittest.mock.patch.object(crypto.ctypes.util, "find_library",
                                            return_value=other):
                self.assertIsNone(crypto._load_libcrypto())
                self.assertIn("EVP_chacha20_poly1305", crypto._LIBCRYPTO_ERROR)

    def test_bytes_like_input_still_works_and_keeps_the_backend(self):
        # bytearray is what the pure-python code accepted before; it must keep working
        # (the libcrypto path takes bytes only, so these calls go to python), and it
        # must not be mistaken for a libcrypto failure.
        key, nonce = bytes(range(32)), bytes(range(12))
        blob = crypto.chacha20poly1305_encrypt(bytearray(key), bytearray(nonce),
                                               bytearray(b"hi"), bytearray())
        self.assertEqual(crypto.chacha20poly1305_decrypt(bytearray(key), bytearray(nonce),
                                                         blob, bytearray()), b"hi")
        self.assertEqual(crypto.aead_backend(), "libcrypto" if LIBCRYPTO else "python")
        self.assertEqual(blob, crypto._chacha20poly1305_encrypt_python(key, nonce, b"hi"))

    def test_odd_shapes_raise_what_they_always_raised(self):
        # libcrypto needs a 32-byte key and a 12-byte nonce; anything else takes the
        # pure-python path and fails there, exactly as before.
        with self.assertRaises(struct.error):
            crypto.chacha20poly1305_encrypt(b"k" * 16, b"n" * 12, b"x")
        with self.assertRaises(struct.error):
            crypto.chacha20poly1305_encrypt(bytes(32), b"n" * 5, b"x")
        with self.assertRaises(ValueError):     # shorter than a tag
            crypto.chacha20poly1305_decrypt(bytes(32), bytes(12), b"short")
        self.assertEqual(crypto.aead_backend(), "libcrypto" if LIBCRYPTO else "python")


class ForcedPurePython(unittest.TestCase):
    """`OMCLIP_CRYPTO=python` must carry the daemon's AEAD with no libcrypto at all."""

    def _child(self, *args):
        env = dict(os.environ, OMCLIP_CRYPTO="python", OMCLIP_CRYPTO_FORCED="1")
        return subprocess.run([sys.executable, *args], cwd=_support.HERE, env=env,
                              capture_output=True, text=True, timeout=300)

    def test_the_environment_variable_selects_the_pure_python_path(self):
        proc = self._child("-c", "import _support; from omclip import crypto; "
                                 "print(crypto.aead_backend()); print(crypto._LIBCRYPTO_ERROR)")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.splitlines()[0], "python")
        self.assertIn("OMCLIP_CRYPTO", proc.stdout)

    def test_the_whole_module_passes_with_libcrypto_disabled(self):
        if os.environ.get("OMCLIP_CRYPTO_FORCED") == "1":
            self.skipTest("this is already the forced-pure interpreter")
        proc = self._child("-m", "unittest", "test_crypto", "-v")
        self.assertEqual(proc.returncode, 0, proc.stderr[-4000:])
        # The three libcrypto-only parity tests, plus this one's recursion guard.
        self.assertIn("OK (skipped=4)", proc.stderr)
        self.assertIn("test_rfc_vector", proc.stderr)   # the public API ran under python


class Hkdf(unittest.TestCase):
    def test_sha512_vectors(self):
        self.assertEqual(
            crypto.hkdf_sha512(bytes.fromhex("0b" * 22),
                               bytes.fromhex("000102030405060708090a0b0c"),
                               bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42).hex(),
            "832390086cda71fb47625bb5ceb168e4c8e26a1a16ed34d9fc7fe92c1481579338da362cb8d9f925d7cb")
        self.assertEqual(crypto.hkdf_sha512(b"\x00" * 80, b"", b"", 32).hex(),
                         "87aa2767b7e2ea8c1934323cbc8ce27318b2b73ab6cd2894c7a6ce6e03a6d0a8")

    def test_length(self):
        self.assertEqual(len(crypto.hkdf_sha512(b"x", b"", b"", 32)), 32)
        self.assertEqual(len(crypto.hkdf_sha512(b"x", b"", b"", 100)), 100)


class Ed25519(unittest.TestCase):
    def test_rfc8032_empty_message_vector(self):
        sk = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        self.assertEqual(crypto.ed25519_sign(sk, b"").hex(),
                         "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555"
                         "fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")

    def test_deterministic(self):
        sk = bytes(range(32))
        self.assertEqual(crypto.ed25519_sign(sk, b"m"), crypto.ed25519_sign(sk, b"m"))
        self.assertNotEqual(crypto.ed25519_sign(sk, b"m"), crypto.ed25519_sign(sk, b"n"))


class Tlv8(unittest.TestCase):
    def test_encode_decode(self):
        blob = crypto.tlv8_encode([(0x03, b"\x01\x02"), (0x19, b"\x01"), (0x06, b"\x04")])
        self.assertEqual(blob.hex(), "03020102190101060104")
        self.assertEqual({hex(k): v.hex() for k, v in crypto.tlv8_decode(blob).items()},
                         {"0x3": "0102", "0x19": "01", "0x6": "04"})

    def test_values_over_255_bytes_are_chunked(self):
        value = bytes(range(256))
        blob = crypto.tlv8_encode([(0x05, value)])
        self.assertEqual(len(blob), 2 + 255 + 2 + 1)
        self.assertEqual(blob[0], 0x05)
        self.assertEqual(blob[1], 255)
        self.assertEqual(blob[257], 0x05)
        self.assertEqual(crypto.tlv8_decode(blob)[0x05], value)

    def test_empty_value(self):
        blob = crypto.tlv8_encode([(0x0A, b"")])
        self.assertEqual(blob.hex(), "0a00")
        self.assertEqual(crypto.tlv8_decode(blob), {0x0A: b""})


class Opack(unittest.TestCase):
    def test_roundtrip_scalars(self):
        for value in (None, True, False, 0, 7, 0x27, 0x28, 0xFF, 0x100, 0x10000, 0x100000000,
                      b"", b"\x00" * 0x20, b"\x01" * 0x21, "", "x" * 0x20, "y" * 0x21,
                      [1, 2, 3], {"a": 1}, [None, True, "s"]):
            blob = crypto.opack_encode(value)
            decoded, trailing = crypto.opack_decode(blob)
            self.assertEqual(decoded, value, "roundtrip %r" % (value,))
            self.assertEqual(trailing, 0)

    def test_known_bytes(self):
        # pyatv dialect: small ints are 0x08|n, short strings 0x40|len, dicts 0xE0|count.
        self.assertEqual(crypto.opack_encode({"_t": 2}).hex(), "e1425f740a")
        self.assertEqual(crypto.opack_encode({"_i": "_systemInfo", "_t": 2, "_x": 1, "_c": {}})
                         .hex(), "e4425f694b5f73797374656d496e666f425f740a425f7809425f63e0")

    def test_long_dict_and_list_use_the_endless_form(self):
        value = {("k%02d" % i): i for i in range(20)}
        blob = crypto.opack_encode(value)
        self.assertEqual(blob[0], 0xEF)
        self.assertEqual(blob[-1], 0x03)
        self.assertEqual(crypto.opack_decode(blob)[0], value)
        raw = list(range(20))
        blob = crypto.opack_encode(raw)
        self.assertEqual(blob[0], 0xDF)
        self.assertEqual(crypto.opack_decode(blob)[0], raw)

    def test_object_references_decode(self):
        # The (pyatv-compatible) encoder always writes values in full; the decoder must
        # still resolve the reference form a real peer may send: a repeat of an
        # already-packed value is 0xA0|index into the ordered object table, which holds
        # every multi-byte value in first-appearance order ("a" is index 0 here).
        ref = bytes.fromhex("e241614b68656c6c6f20776f726c644162a1")
        decoded, trailing = crypto.opack_decode(ref)
        self.assertEqual(decoded, {"a": "hello world", "b": "hello world"})
        self.assertEqual(trailing, 0)
        # ...and what the encoder produces round-trips unchanged.
        whole = crypto.opack_encode({"a": "hello world", "b": "hello world"})
        self.assertEqual(crypto.opack_decode(whole)[0],
                         {"a": "hello world", "b": "hello world"})
        self.assertNotEqual(whole, ref, "encoder writes repeats in full, deliberately")

    def test_unknown_marker_raises(self):
        with self.assertRaises(ValueError):
            crypto.opack_decode(b"\xff")


if __name__ == "__main__":
    unittest.main()
