"""The companion-stream client: request archive, V2 exchange, file bodies, caps, refusals.

Every test drives `bulk.fetch` against a loopback holder over a socketpair, so nothing
here can reach the Mac: `fetch` takes its TLS connection and its mDNS/AWDL lookup as
parameters and these tests pass their own. The frames the fake holder sends are the ones
measured on the wire — the request archive and the tag/MessagePack bodies are pinned
against bytes the live Mac actually accepted (2026-10-14), so a change that would stop
working on the real peer fails here first.
"""

import hashlib
import json
import os
import plistlib
import shutil
import socket
import tempfile
import threading
import time
import unittest
import unittest.mock
import zlib

import _support
from omclip import bulk, daemon as daemonmod, discovery, log as logmod, pasteboard, paths, status

#: The descriptor the live Mac sent for the 12:00 generation (the same fetch whose
#: payload and file body are recorded in the wire fixtures below).
LIVE_EXTRA_HEX = (
    "62706c6973743030d30102030405065b617574686f725f646174615c626f6e6a6f75725f6e616d655f100f6d65"
    "73736167655f76657273696f6e4f10ca62706c6973743030d301020304050659756e697175655f69645a6d616e"
    "616765725f696459636c69656e745f69645f102430454635324536322d433638322d344537382d393846432d31"
    "46463938333437313237425f102434353632414434352d394533342d344437372d394139322d46343436323030"
    "32323541315f102442353335383834382d374333422d343231302d384246392d35303132434133304438324308"
    "0f19242e557c00000000000001010000000000000007000000000000000000000000000000a35c393762316637"
    "33343664313910010008000f001b0028003a010701140000000000000201000000000000000700000000000000"
    "000000000000000116"
)
#: The archive `bulk.request_archive` must produce for `LIVE_EXTRA_HEX`: the bytes the
#: prototype sent to the Mac at 12:00:14, answered with `CompanionStreamConnectResponse:
#: true` 240 ms later. 690 bytes.
LIVE_REQUEST_SHA256 = "4b3b5a0199ac40e0359714591c383396c4e2db908f70524d7bf63134258975cb"
LIVE_REQUEST_BYTES = 690
#: `UAStreamHandler` tag 9 for `{"totalSize": 2309236}`, exactly as it arrived.
LIVE_AUX_BODY = bytes.fromhex("4d50030581a9746f74616c53697a65ce00233c74")
LIVE_AUX_FRAME = bytes.fromhex("430100000009000000144d50030581a9746f74616c53697a65ce00233c74")
FILE_UUID = "775DF18B-E262-48C2-8AA6-D16978131DF6"
FILE_UUID_BYTES = bytes.fromhex("775df18be26248c28aa6d16978131df6")


def live_descriptor():
    """A bulk pasteboard carrying the descriptor the live Mac sent."""
    archive = _support.pasteboard_archive(
        items=[{"public.utf8-plain-text": {"offset": 0, "size": 0}}],
        extra=bytes.fromhex(LIVE_EXTRA_HEX), data_size=308686, extra_type=1)
    return pasteboard.parse_pasteboard_archive(archive)


def bulk_pb(*, unique_id="CA5C0FF4-C1AB-4D4A-8C43-EFDF9FBE896A", data_size=308686,
            items=None, extra=None):
    """A bulk generation as `parse_pasteboard_archive` hands it to the daemon."""
    archive = _support.pasteboard_archive(
        items=items or [{"public.utf8-plain-text": {"offset": 0, "size": data_size,
                                                    "preferred": True}}],
        extra=extra if extra is not None else _support.bulk_descriptor(
            unique_id=unique_id, manager_id="MGR", client_id="CLI",
            bonjour="97b1f7346d19"),
        data_size=data_size, extra_type=1)
    return pasteboard.parse_pasteboard_archive(archive)


def file_pb(*, data_size=308686):
    """A bulk generation for a Finder file copy: URL, name, icon and a file UUID."""
    return bulk_pb(data_size=data_size, items=[{
        "public.file-url": {"offset": 0, "size": 46, "uuid": {"NS.uuidbytes":
                                                             FILE_UUID_BYTES}},
        "public.utf8-plain-text": {"offset": 46, "size": 17, "preferred": True},
        "com.apple.icns": {"offset": 63, "size": data_size - 63}}])


#: The blob pool a file record carries: the xattr/ACL bytes, written *after* the data.
#: Taken from the live archive (84 bytes, `com.apple.quarantine`, length-prefixed record).
AAR_POOL = (b"\x54\x00\x00\x00com.apple.quarantine\x00"
            b"0081;6acc469c;sharingd;4CC8F9FD-87FD-4437-AFA7-321958ED285F")


def aar(name, data, *, stored=True, wrapper_record=True, records=1, pool=AAR_POOL,
        digests=True):
    """A minimal AppleArchive in the shape the holder writes one.

    `AA01`, a two-byte *header length*, the fields, then what the entry carries that is not
    a field: for a file the data first and the xattr/ACL blob **pool after it**, for the
    wrapper record (a directory) just its pool. So the file's bytes are
    `archive[at + header : at + header + DAT]` and the archive's last `DAT` bytes are the
    data shifted by `len(pool)` with the pool appended — the bug this pins. The field
    grammar is the measured one (`TYP1`, `PATP`, `SIZ4`, `DATB`, `XATA`, `CKSF`, `SH1G`,
    `SH2H`), including the record's own `SH1`/`SH2` digests of the data, which the decoder
    now checks; `digests=False` writes a record without them.
    """
    def record(fields):
        # The record's header length counts everything from the magic to the end of the
        # field block (measured: 278 + 179 = 457, the live record's data start), so it is
        # the magic, the length itself and the fields.
        return b"AA01" + (6 + len(fields)).to_bytes(2, "little") + fields

    def file_fields(path, size, stored_len, digest):
        out = bytearray()
        out += b"TYP1F"
        out += b"UID2" + (501).to_bytes(2, "little")
        out += b"GID1" + bytes([20])
        out += b"FLG1" + b"\x00"
        out += b"MOD2" + (0o644).to_bytes(2, "little")
        out += b"MTM" + b"T" + (1791771784).to_bytes(8, "little") + (0).to_bytes(4, "little")
        out += b"CTM" + b"S" + (1791771784).to_bytes(8, "little")
        out += b"INO4" + (106159411).to_bytes(4, "little")
        out += b"SIZ4" + size.to_bytes(4, "little")
        out += b"PATP" + len(path).to_bytes(2, "little") + path.encode()
        out += b"DATB" + stored_len.to_bytes(4, "little")
        out += b"XATA" + len(pool).to_bytes(2, "little")
        out += b"CKSF" + (0x1A2B3C4D).to_bytes(4, "little")
        if digest:
            out += b"SH1G" + hashlib.sha1(data).digest()
            out += b"SH2H" + hashlib.sha256(data).digest()
        return bytes(out)

    def wrapper_fields():
        out = bytearray()
        out += b"TYP1D"
        out += b"UID2" + (501).to_bytes(2, "little")
        out += b"GID1" + bytes([20])
        out += b"FLG1" + b"\x00"
        out += b"MOD2" + (0o755).to_bytes(2, "little")
        out += b"MTM" + b"T" + (1791771784).to_bytes(8, "little") + (0).to_bytes(4, "little")
        out += b"INO2" + (2).to_bytes(2, "little")
        out += b"PATP" + (0).to_bytes(2, "little")
        out += b"XATA" + len(pool).to_bytes(2, "little")
        out += b"ACLA" + len(pool).to_bytes(2, "little")
        return bytes(out)

    body = data if stored else _raw_deflate(data)
    out = b""
    if wrapper_record:
        out += record(wrapper_fields()) + pool          # a directory: fields then its pool
    for index in range(records):
        entry_name = name if index == 0 else "%s%d" % (name, index)
        out += record(file_fields(entry_name, len(data), len(body), digests))
        if index == 0:
            out += body + pool                          # the data, then the entry's pool
    return out


def _raw_deflate(data):
    compressor = zlib.compressobj(9, zlib.DEFLATED, -zlib.MAX_WBITS)
    return compressor.compress(data) + compressor.flush()


def peer_archive(pairs):
    """An NSKeyedArchiver archive in the holder's own style: raw plist values, class stubs.

    `bulk.KeyedArchiver` writes the same *information* in the other shape the peer accepts,
    so the accept reply is built by hand here: this is what `decode_archive` has to cope
    with on a real connection.
    """
    objects = ["$null", None]                      # 0 = $null, 1 = the root (below)
    stub = len(objects)
    objects.append({"$classname": "NSDictionary", "$classes": ["NSDictionary", "NSObject"]})
    keys, values = [], []
    for key, value in pairs:
        keys.append(len(objects))
        objects.append(key)
        values.append(len(objects))
        objects.append(int(value) if isinstance(value, bool) else value)
    objects[1] = {"$class": plistlib.UID(stub),
                  "NS.keys": [plistlib.UID(index) for index in keys],
                  "NS.objects": [plistlib.UID(index) for index in values]}
    return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000,
                           "$objects": objects, "$top": {"root": plistlib.UID(1)}},
                          fmt=plistlib.FMT_BINARY)


def accept_frame(accepted=True):
    body = peer_archive([("StreamMessageType", 1), ("StreamMessageVersion", 1),
                         ("CompanionStreamConnectResponse", accepted)])
    return b"\x01" + len(body).to_bytes(4, "big") + body


def chunks(blob, size=64 * 1024):
    out = [blob[i:i + size] for i in range(0, len(blob), size)] or [b""]
    return out


class FakeHolder(threading.Thread):
    """A loopback `_continuity._tcp` holder: accept reply, then one scripted exchange.

    `respond` gets the socket and is expected to serve the V2 messages the client asks
    for; it may raise, which the test then sees as `self.error`.
    """

    def __init__(self, respond, accept=True, opener=b""):
        super().__init__(daemon=True)
        self.client_end, self.holder_end = socket.socketpair()
        self.client_end.settimeout(10.0)
        self.holder_end.settimeout(10.0)
        self.respond = respond
        self.accept = accept
        self.opener = opener
        self.request = None
        self.header = None
        self.error = None
        self.connected = False

    def run(self):
        try:
            header = self._read_exact(5)
            self.header = header
            length = int.from_bytes(header[1:5], "big")
            self.request = self._read_exact(length)
            self.connected = True
            self.holder_end.sendall(accept_frame(self.accept))
            if not self.accept:
                return
            if self.opener:
                self.holder_end.sendall(self.opener)
            self.respond(self)
        except Exception as exc:                       # noqa: BLE001 - asserted by tests
            self.error = exc
        finally:
            self.holder_end.close()

    def _read_exact(self, count):
        out = b""
        while len(out) < count:
            got = self.holder_end.recv(count - len(out))
            if not got:
                raise AssertionError("client closed after %d of %d bytes" % (len(out), count))
            out += got
        return out

    def read_message(self, timeout=5.0):
        """One V2 message from the client → (tag, body)."""
        self.holder_end.settimeout(timeout)
        header = self._read_exact(10)
        assert header[0:2] == b"C\x01", header.hex()
        tag, length = int.from_bytes(header[2:6], "big"), int.from_bytes(header[6:10], "big")
        return tag, (self._read_exact(length) if length else b"")

    def send_message(self, tag, obj):
        self.holder_end.sendall(bulk.tag_message(tag, obj))

    def send_raw(self, data):
        self.holder_end.sendall(data)

    def connector(self, host, port, keys_dir, timeout, iface=None):
        self.endpoint = (host, port, keys_dir, timeout, iface)
        return self.client_end


def fetch(pb, holder, *, max_bytes=256 * 1024 * 1024, download_dir=None, resolver=None,
          timeout=5.0):
    """`bulk.fetch` with the loopback holder wired in and the lookup stubbed out."""
    if resolver is None:
        resolver = lambda descriptor, address=None, iface=None: ("127.0.0.1", 8771)
    return bulk.fetch(pb, keys_dir="/nonexistent", max_bytes=max_bytes,
                      download_dir=download_dir, connector=holder.connector,
                      resolver=resolver, timeout=timeout)


class RequestArchive(unittest.TestCase):
    """The request: the crux is that `RequestAuthorData` is the blob, not the dictionary."""

    def test_request_matches_the_bytes_the_live_mac_accepted(self):
        descriptor = bulk.descriptor_of(live_descriptor())
        archive = bulk.request_archive(descriptor)
        self.assertEqual(len(archive), LIVE_REQUEST_BYTES)
        self.assertEqual(hashlib.sha256(archive).hexdigest(), LIVE_REQUEST_SHA256)

    def test_author_data_is_the_blob_and_not_the_parsed_dictionary(self):
        pb = live_descriptor()
        descriptor = bulk.descriptor_of(pb)
        self.assertEqual(descriptor["bonjour_name"], "97b1f7346d19")
        self.assertEqual(descriptor["unique_id"], "0EF52E62-C682-4E78-98FC-1FF98347127B")
        # `pasteboard` decodes the nested author data for the evidence files; the blob is
        # what the peer parses with `+[SFCompanionService serviceFromAuthorData:]`.
        self.assertIsInstance(pb["descriptor"]["author_data"], dict)
        self.assertEqual(descriptor["author_data"][:8], b"bplist00")
        decoded = bulk.decode_archive(bulk.request_archive(descriptor))
        self.assertEqual(decoded["StreamMessageType"], 0)
        self.assertEqual(decoded["StreamMessageVersion"], 1)
        self.assertIsInstance(decoded["RequestAuthorData"], bytes)
        self.assertEqual(decoded["RequestAuthorData"], descriptor["author_data"])
        self.assertEqual(plistlib.loads(decoded["RequestAuthorData"])["unique_id"],
                         descriptor["unique_id"])

    def test_archive_shape_is_a_keyed_archive(self):
        archive = bulk.request_archive({"author_data": b"blob"})
        blob = plistlib.loads(archive)
        self.assertEqual(blob["$archiver"], "NSKeyedArchiver")
        self.assertEqual(blob["$version"], 100000)
        self.assertEqual(blob["$objects"][0], "$null")

        def deref(ref):
            return blob["$objects"][ref.data]

        root = deref(blob["$top"]["root"])
        self.assertEqual(deref(root["$class"])["$classname"], "NSDictionary")
        self.assertEqual([deref(ref) for ref in root["NS.keys"]],
                         ["StreamMessageType", "StreamMessageVersion", "RequestAuthorData"])
        kind, number = deref(root["NS.objects"][0]), deref(root["NS.objects"][1])
        self.assertEqual(deref(kind["$class"])["$classname"], "NSNumber")
        self.assertEqual(kind["NS.number"], 0)
        self.assertEqual(number["NS.number"], 1)
        data = deref(root["NS.objects"][2])
        self.assertEqual(deref(data["$class"])["$classname"], "NSData")
        self.assertEqual(data["NS.data"], b"blob")

    def test_frame_header_is_a_type_byte_and_a_big_endian_length(self):
        framed = bulk.frame(b"xyz")
        self.assertEqual(framed, b"\x01\x00\x00\x00\x03xyz")

    def test_generation_key_is_per_pasteboard_content_not_per_announcement(self):
        # The measured reality: the sender re-mints `unique_id` on every response while the
        # item table stays identical, so the identity is the item UUIDs + DataSize.
        first = bulk_pb(unique_id="AAA")
        again = bulk_pb(unique_id="BBB")
        self.assertEqual(bulk.generation_key(first), bulk.generation_key(again))
        self.assertEqual(bulk.generation_key(first), bulk.generation_key(bulk_pb()))
        # A different pasteboard (different item UUIDs / sizes) is a different identity.
        self.assertNotEqual(bulk.generation_key(first), bulk.generation_key(file_pb()))
        self.assertNotEqual(bulk.generation_key(first),
                            bulk.generation_key(bulk_pb(unique_id="AAA", data_size=7)))
        self.assertNotEqual(bulk.generation_key(first),
                            bulk.generation_key(bulk_pb(unique_id="AAA", items=[
                                {"public.utf8-plain-text": {"offset": 0, "size": 5}}])))


class Packing(unittest.TestCase):
    """`_UACopyPackedDataForObject` output, pinned against the bytes the holder sent."""

    def test_aux_info_frame_matches_the_wire(self):
        self.assertEqual(bulk.tag_message(bulk.TAG_AUX_INFO, {"totalSize": 2309236}),
                         LIVE_AUX_FRAME)

    def test_unpack_is_the_inverse_and_rejects_foreign_bodies(self):
        self.assertEqual(bulk.unpack_message(LIVE_AUX_BODY), {"totalSize": 2309236})
        self.assertIsNone(bulk.unpack_message(b"UCHB"))
        self.assertIsNone(bulk.unpack_message(bulk.PACK_PREFIX + b"\xc1"))
        self.assertEqual(bulk.unpack_message(bulk.pack_message(
            {"supportsCompression": False, "uuid": FILE_UUID})),
            {"supportsCompression": False, "uuid": FILE_UUID})


class Exchange(unittest.TestCase):
    """The accept handshake and the driven V2 exchange."""

    def serve(self, holder, wrapper_archive, blob, aux=None):
        def respond(peer):
            peer.read_message()                       # tag 3 infoRequest
            if aux is not None:
                peer.send_message(bulk.TAG_AUX_INFO, {"totalSize": aux})
            peer.send_message(bulk.TAG_INFO_RESPONSE, {"data": wrapper_archive})
            tag, _body = peer.read_message()          # tag 5 dataRequest
            assert tag == bulk.TAG_DATA_REQUEST, tag
            parts = chunks(blob)
            for index, part in enumerate(parts, 1):
                peer.send_message(bulk.TAG_DATA_RESPONSE,
                                  {"data": part, "packetNum": index,
                                   "totalNum": len(parts)})
        return respond

    def test_fetches_a_blob_whose_size_equals_data_size(self):
        body = b"Braun : Designed to Keep"
        wrapper = _support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": len(body), "preferred": True}}],
            extra=b"", data_size=len(body))
        holder = FakeHolder(self.serve(self, wrapper, body, aux=len(body)))
        holder.start()
        payload = fetch(bulk_pb(data_size=len(body)), holder)
        holder.join(timeout=5)
        self.assertIsNone(holder.error, holder.error)
        self.assertEqual(payload.blob, body)
        self.assertEqual(payload.data_size, len(body))
        self.assertEqual(payload.endpoint, ("127.0.0.1", 8771))
        # The request arrives as one frame: the type byte, a big-endian length, the archive.
        self.assertEqual(holder.header[0], 1)
        self.assertEqual(int.from_bytes(holder.header[1:5], "big"), len(holder.request))
        self.assertEqual(plistlib.loads(holder.request)["$archiver"], "NSKeyedArchiver")
        # ... and the fetched generation is a plain pasteboard for `decide()`.
        inline = payload.as_inline()
        self.assertFalse(inline["bulk"])
        self.assertEqual(inline["extra_data"], body)
        self.assertTrue(inline["fetched"])
        self.assertEqual(pasteboard.best_representation(inline), ("public.utf8-plain-text",
                                                                 body))
        self.assertEqual(pasteboard.digest_of("public.utf8-plain-text", body),
                         pasteboard.decide(inline).digest)

    def test_multi_chunk_blob_is_reassembled(self):
        body = bytes(range(256)) * 700                    # 179200 bytes: three chunks
        wrapper = _support.pasteboard_archive(
            [{"public.png": {"offset": 0, "size": len(body), "preferred": True}}],
            extra=b"", data_size=len(body))
        holder = FakeHolder(self.serve(self, wrapper, body))
        holder.start()
        payload = fetch(bulk_pb(data_size=len(body)), holder)
        holder.join(timeout=5)
        self.assertIsNone(holder.error, holder.error)
        self.assertEqual(payload.blob, body)
        self.assertEqual(len(chunks(body)), 3)

    def test_empty_info_response_means_the_holder_has_nothing_to_send(self):
        # The stale-generation case measured on the live Mac: tag 4 carries `{}` because
        # `-sendPasteboardInfoResponse` only sets `data` when it has a pasteboard.
        holder = FakeHolder(lambda peer: (peer.read_message(),
                                          peer.send_message(bulk.TAG_INFO_RESPONSE, {})))
        holder.start()
        with self.assertRaises(bulk.BulkError) as caught:
            fetch(bulk_pb(), holder)
        holder.join(timeout=5)
        self.assertIn("no pasteboard to send", str(caught.exception))

    def test_unpackable_info_response_is_an_error_not_a_crash(self):
        holder = FakeHolder(lambda peer: (peer.read_message(),
                                          peer.send_message(bulk.TAG_INFO_RESPONSE,
                                                            {"data": None})))
        holder.start()
        with self.assertRaises(bulk.BulkError):
            fetch(bulk_pb(), holder)
        holder.join(timeout=5)

    def test_refused_stream_request_is_reported(self):
        holder = FakeHolder(lambda peer: None, accept=False)
        holder.start()
        with self.assertRaises(bulk.BulkError) as caught:
            fetch(bulk_pb(), holder)
        holder.join(timeout=5)
        self.assertIn("refused", str(caught.exception))

    def test_v1_push_framing_is_named_rather_than_mis_parsed(self):
        holder = FakeHolder(lambda peer: None, opener=b"===")
        holder.start()
        with self.assertRaises(bulk.BulkError) as caught:
            fetch(bulk_pb(), holder)
        holder.join(timeout=5)
        self.assertIn("coder V1", str(caught.exception))

    def test_blob_beyond_max_bytes_is_refused_before_connecting(self):
        called = []

        def connector(*args, **kwargs):
            called.append(args)
            raise AssertionError("must not connect")

        with self.assertRaises(bulk.Refused):
            bulk.fetch(bulk_pb(data_size=308686), keys_dir="/nonexistent",
                       max_bytes=1024, download_dir=None, connector=connector,
                       resolver=lambda *a, **k: ("127.0.0.1", 1))
        self.assertEqual(called, [])

    def test_no_identity_is_a_refusal_not_an_error(self):
        holder = FakeHolder(lambda peer: None)
        with self.assertRaises(bulk.Refused):
            bulk.connect("127.0.0.1", 1, "/nonexistent", 0.1)     # never dials
        holder.client_end.close()
        holder.holder_end.close()

    def test_client_context_asks_for_a_client_certificate_and_does_not_verify(self):
        import ssl
        recorded = {}

        class Recorder:
            def __init__(self, protocol):
                recorded["protocol"] = protocol

            def __setattr__(self, name, value):
                recorded[name] = value

            def load_cert_chain(self, cert, key):
                recorded["chain"] = (cert, key)

        directory = tempfile.mkdtemp(prefix="omclip-bulk-")
        try:
            for name in ("certificate.pem", "key.pem"):
                with open(os.path.join(directory, name), "w") as fh:
                    fh.write("x")
            saved = ssl.SSLContext
            ssl.SSLContext = Recorder
            try:
                bulk.client_context(directory)
            finally:
                ssl.SSLContext = saved
        finally:
            shutil.rmtree(directory, ignore_errors=True)
        self.assertEqual(recorded["protocol"], ssl.PROTOCOL_TLS_CLIENT)
        self.assertEqual(recorded["verify_mode"], ssl.CERT_NONE)
        self.assertFalse(recorded["check_hostname"])
        self.assertEqual(recorded["chain"][0], os.path.join(directory, "certificate.pem"))


class FileBodies(unittest.TestCase):
    """File bodies: streamed to disk, capped, never overwriting, never guessed at."""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="omclip-bulk-")

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def serve(self, wrapper_archive, blob, archive_bytes, *, chunks_of=64 * 1024):
        def respond(peer):
            peer.read_message()
            peer.send_message(bulk.TAG_INFO_RESPONSE, {"data": wrapper_archive})
            peer.read_message()
            parts = chunks(blob)
            for index, part in enumerate(parts, 1):
                peer.send_message(bulk.TAG_DATA_RESPONSE,
                                  {"data": part, "packetNum": index, "totalNum": len(parts)})
            tag, body = peer.read_message()
            assert tag == bulk.TAG_FILE_REQUEST, tag
            request = bulk.unpack_message(body)
            assert request["uuid"] == FILE_UUID, request
            parts = [archive_bytes[i:i + chunks_of]
                     for i in range(0, len(archive_bytes), chunks_of)]
            for index, part in enumerate(parts, 1):
                peer.send_message(bulk.TAG_FILE_RESPONSE,
                                  {"data": part, "packetNum": index, "totalNum": len(parts),
                                   "uuid": request["uuid"]})
        return respond

    def wrapper(self, blob):
        return _support.pasteboard_archive(
            [{"public.file-url": {"offset": 0, "size": 46,
                                  "uuid": {"NS.uuidbytes": FILE_UUID_BYTES}},
              "public.utf8-plain-text": {"offset": 46, "size": 17, "preferred": True}}],
            extra=b"", data_size=len(blob))

    def test_file_body_is_landed_with_its_name_size_and_digest(self):
        body = b"file:///Users/user/Downloads/stockblob-l2m.bin"[:46]
        payload_blob = body + b"stockblob-l2m.bin"
        content = bytes(range(256)) * 400                     # 102400 bytes
        archive_bytes = aar("stockblob-l2m.bin", content)
        holder = FakeHolder(self.serve(self.wrapper(payload_blob), payload_blob,
                                       archive_bytes))
        holder.start()
        payload = fetch(file_pb(data_size=len(payload_blob)), holder,
                        download_dir=self.directory)
        holder.join(timeout=5)
        self.assertIsNone(holder.error, holder.error)
        self.assertEqual(payload.files[0].name, "stockblob-l2m.bin")
        self.assertEqual(payload.files[0].bytes, len(content))
        self.assertEqual(payload.files[0].sha256, hashlib.sha256(content).hexdigest())
        self.assertEqual(payload.files[0].uri,
                         "file://" + os.path.join(self.directory, "stockblob-l2m.bin"))
        with open(payload.files[0].path, "rb") as fh:
            self.assertEqual(fh.read(), content)
        # Nothing half-written is left behind.
        self.assertEqual([n for n in os.listdir(self.directory) if n.endswith(".part")], [])
        # The file is what the generation is decided to be.
        decision = pasteboard.decide(payload.as_inline(), file_uri=payload.files[0].uri)
        self.assertEqual(decision.reason, "mirror")
        self.assertEqual(decision.uti, "public.file-url")
        self.assertEqual(decision.data, payload.files[0].uri.encode())

    def test_a_deflated_body_is_decoded_too(self):
        content = b"omclip" * 3000
        archive_bytes = aar("notes.txt", content, stored=False)
        payload_blob = b"notes.txt"
        holder = FakeHolder(self.serve(self.wrapper(payload_blob), payload_blob,
                                       archive_bytes))
        holder.start()
        payload = fetch(file_pb(data_size=len(payload_blob)), holder,
                        download_dir=self.directory)
        holder.join(timeout=5)
        self.assertIsNone(holder.error, holder.error)
        self.assertEqual(payload.files[0].bytes, len(content))
        with open(payload.files[0].path, "rb") as fh:
            self.assertEqual(fh.read(), content)

    def test_an_oversize_file_is_refused_and_the_pasteboard_still_arrives(self):
        content = bytes(range(256)) * 400
        archive_bytes = aar("big.bin", content)
        payload_blob = b"big.bin"
        holder = FakeHolder(self.serve(self.wrapper(payload_blob), payload_blob,
                                       archive_bytes))
        holder.start()
        payload = fetch(file_pb(data_size=len(payload_blob)), holder,
                        download_dir=self.directory, max_bytes=len(payload_blob) + 4096)
        holder.join(timeout=5)
        self.assertIsNone(holder.error, holder.error)
        self.assertEqual(payload.blob, payload_blob)
        self.assertEqual(payload.files, [])
        self.assertEqual(len(payload.refused), 1)
        self.assertTrue(payload.refused[0]["oversize"])
        self.assertEqual(os.listdir(self.directory), [], "nothing written for a refusal")

    def test_a_layout_we_cannot_decode_is_refused_not_guessed(self):
        content = b"two files"
        archive_bytes = aar("a.bin", content, records=2)
        payload_blob = b"a.bin"
        holder = FakeHolder(self.serve(self.wrapper(payload_blob), payload_blob,
                                       archive_bytes))
        holder.start()
        payload = fetch(file_pb(data_size=len(payload_blob)), holder,
                        download_dir=self.directory)
        holder.join(timeout=5)
        self.assertIsNone(holder.error, holder.error)
        self.assertEqual(payload.files, [])
        self.assertIn("file entries", payload.refused[0]["error"])
        self.assertEqual(os.listdir(self.directory), [])

    def test_a_body_that_never_arrives_does_not_cost_the_pasteboard(self):
        payload_blob = b"file:///tmp/x.bin"

        def respond(peer):
            peer.read_message()
            peer.send_message(bulk.TAG_INFO_RESPONSE, {"data": self.wrapper(payload_blob)})
            peer.read_message()
            peer.send_message(bulk.TAG_DATA_RESPONSE,
                              {"data": payload_blob, "packetNum": 1, "totalNum": 1})
            peer.read_message()                    # the file request: never answered

        holder = FakeHolder(respond)
        holder.start()
        payload = fetch(file_pb(data_size=len(payload_blob)), holder,
                        download_dir=self.directory, timeout=2.0)
        holder.join(timeout=5)
        self.assertEqual(payload.blob, payload_blob)
        self.assertEqual(payload.files, [])
        self.assertTrue(payload.refused)
        self.assertEqual(os.listdir(self.directory), [])

    def test_file_uuid_is_upper_case_as_the_holder_spells_it(self):
        wrapper = pasteboard.parse_pasteboard_archive(self.wrapper(b"x" * 46))
        self.assertEqual(bulk._file_uuids(wrapper), [FILE_UUID])


class AppleArchive(unittest.TestCase):
    """The archive decoder, against the layout the holder produces."""

    def setUp(self):
        self.directory = tempfile.mkdtemp(prefix="omclip-bulk-")
        self.path = os.path.join(self.directory, "landed.aar")

    def tearDown(self):
        shutil.rmtree(self.directory, ignore_errors=True)

    def write(self, data):
        with open(self.path, "wb") as fh:
            fh.write(data)

    def test_the_real_archive_shape_is_parsed(self):
        # The measured header of the live 2 MB copy: a wrapper record then the file record.
        data = b"\xaa" * 2048
        self.write(aar("stockblob-l2m.bin", data))
        with open(self.path, "rb") as fh:
            entry = bulk.summary(fh.read(), total=os.path.getsize(self.path))
        self.assertEqual(entry["path"], "stockblob-l2m.bin")
        self.assertEqual(entry["size"], len(data))
        self.assertEqual(entry["data"], len(data))
        self.assertEqual(entry["type"], ord("F"))
        # The record's own header length locates the data, not the archive's total size.
        self.assertEqual(entry["at"] + entry["header"], entry["fields_end"])
        self.assertEqual(entry["sha1"], hashlib.sha1(data).digest())
        self.assertEqual(entry["sha256"], hashlib.sha256(data).digest())

    def test_stored_data_is_the_record_header_end_to_header_end_plus_dat(self):
        data = b"\x00\x01\x02" * 500
        self.write(aar("payload.bin", data))
        landed = bulk.extract_archive(self.path, directory=self.directory,
                                      limit=8 * 1024 * 1024)
        with open(landed.path, "rb") as fh:
            self.assertEqual(fh.read(), data)
        self.assertEqual(landed.sha256, hashlib.sha256(data).hexdigest())

    def test_a_blob_pool_after_the_data_is_never_landed_as_content(self):
        # The bug the live HEIC copies hit: `total - DAT` starts `len(pool)` bytes into the
        # file and appends the pool, so a file of exactly the declared size and the wrong
        # bytes lands. The data starts where the record says, and the tail is not it.
        data = bytes(range(256)) * 20
        archive = aar("payload.bin", data)
        self.assertNotEqual(archive[-len(data):], data, "the tail is shifted by the pool")
        self.write(archive)
        landed = bulk.extract_archive(self.path, directory=self.directory, limit=1 << 20)
        with open(landed.path, "rb") as fh:
            self.assertEqual(fh.read(), data)
        self.assertEqual(landed.bytes, len(data), "the size says nothing on its own")
        self.assertEqual(landed.sha256, hashlib.sha256(data).hexdigest())

    def test_timespec_fields_with_nanoseconds_are_parsed(self):
        fields = bytearray()
        fields += b"TYP1F"
        fields += b"MTMT" + (1791771784).to_bytes(8, "little") + (123456).to_bytes(4, "little")
        fields += b"CTMT" + (1791771784).to_bytes(8, "little") + (654321).to_bytes(4, "little")
        fields += b"SIZ4" + (100).to_bytes(4, "little")
        fields += b"PATP" + (8).to_bytes(2, "little") + b"test.bin"
        fields += b"DATB" + (100).to_bytes(4, "little")
        record = b"AA01" + (6 + len(fields)).to_bytes(2, "little") + fields
        entries = bulk.archive_entries(record + b"x" * 100)
        self.assertEqual(len(entries), 1)
        self.assertEqual(entries[0]["path"], "test.bin")
        self.assertEqual(entries[0]["size"], 100)
        self.assertEqual(entries[0]["type"], ord("F"))

    def test_a_body_whose_digest_does_not_match_is_refused(self):
        data = b"payload" * 100
        archive = bytearray(aar("payload.bin", data))
        at = bytes(archive).rfind(b"SH2H") + 4
        archive[at] ^= 0xFF
        self.write(bytes(archive))
        with self.assertRaises(bulk.Refused) as caught:
            bulk.extract_archive(self.path, directory=self.directory, limit=1 << 20)
        self.assertIn("SHA-256", str(caught.exception))
        self.assertEqual(os.listdir(self.directory), ["landed.aar"], "nothing was kept")

    def test_data_that_runs_past_the_archive_is_refused(self):
        data = b"x" * 4096
        archive = bytearray(aar("odd.bin", data))
        for key in (b"SIZ4", b"DATB"):
            at = bytes(archive).rfind(key) + 4
            archive[at:at + 4] = (len(data) * 4).to_bytes(4, "little")
        self.write(bytes(archive))
        with self.assertRaises(bulk.Refused) as caught:
            bulk.extract_archive(self.path, directory=self.directory, limit=8 << 20)
        self.assertIn("past the", str(caught.exception))
        self.assertEqual(os.listdir(self.directory), ["landed.aar"], "nothing was written")

    def test_the_real_received_archive_slice_decodes_to_the_real_file(self):
        """The live artifact, minimised: real header, real data slice, real blob pool.

        Provenance: the Mac's copy of `IMG_1727.HEIC` on 2026-10-14 (descriptor
        `20261014T124939`, file `B216D8D0-…`, archive sha256 `337125b0…`, 2 845 302 bytes).
        The wrapper record, the file record's fields and header length (179) and the file's
        first 4 096 bytes are verbatim; `SIZ`/`DAT` were rewritten to 4 096 and the record's
        `SH1`/`SH2` to the digests of that slice, and the pool is the real 1 755 bytes that
        followed the real data (`[2843547, 2845302)`, xattrs declared as 1 751). The Mac's
        own sha256 for the full record region `[457, 2843547)` is `42433ea0…`.
        """
        with open(os.path.join(os.path.dirname(__file__), "fixtures",
                               "applearchive-1727.slice.aar"), "rb") as fh:
            archive = fh.read()
        self.write(archive)
        landed = bulk.extract_archive(self.path, directory=self.directory, limit=8 << 20)
        with open(landed.path, "rb") as fh:
            content = fh.read()
        self.assertEqual(content, archive[457:457 + 4096])
        self.assertTrue(content.startswith(b"\x00\x00\x00\x34ftypheic"),
                        "the file's head, not a byte somewhere inside it")
        self.assertEqual(landed.bytes, 4096)
        self.assertEqual(landed.sha256, hashlib.sha256(content).hexdigest())
        self.assertNotEqual(content, archive[-4096:], "the tail was never the file")

    def test_an_existing_file_is_never_overwritten(self):
        data = b"one"
        self.write(aar("same.bin", data))
        first = bulk.extract_archive(self.path, directory=self.directory, limit=1 << 20)
        second = bulk.extract_archive(self.path, directory=self.directory, limit=1 << 20)
        self.assertNotEqual(first.path, second.path)
        # `name` is the name inside the archive; `path` is where it actually landed.
        self.assertEqual(first.name, second.name, "the same entry, landed twice")
        self.assertEqual(os.path.basename(first.path), "same.bin")
        self.assertEqual(os.path.basename(second.path), "same (1).bin")

    def test_a_truncated_or_missing_entry_is_refused(self):
        self.write(b"AA01\x55\x00TYP1F")
        with self.assertRaises(bulk.Refused):
            bulk.extract_archive(self.path, directory=self.directory, limit=1 << 20)
        self.write(b"not an archive at all")
        with self.assertRaises(bulk.Refused):
            bulk.extract_archive(self.path, directory=self.directory, limit=1 << 20)

    def test_a_size_the_archive_cannot_support_is_refused(self):
        data = b"x" * 100000
        archive = aar("odd.bin", data)
        # A `DAT` that does not match `SIZ` is not a stored body this decoder can trust,
        # and the bytes after the header are not a deflate stream: refused, not guessed at.
        broken = bytearray(archive)
        at = archive.rfind(b"DATB") + 4
        broken[at:at + 4] = (7).to_bytes(4, "little")
        self.write(bytes(broken))
        with self.assertRaises(bulk.Refused) as caught:
            bulk.extract_archive(self.path, directory=self.directory, limit=8 << 20)
        self.assertIn("decode", str(caught.exception))

        self.write(archive)
        broken = bytearray(archive)
        at = archive.rfind(b"SIZ4") + 4
        broken[at:at + 4] = ((1 << 20) + 1).to_bytes(4, "little")
        self.write(bytes(broken))
        with self.assertRaises(bulk.Refused) as caught:
            bulk.extract_archive(self.path, directory=self.directory, limit=1 << 20)
        self.assertIn("max_bytes", str(caught.exception))
        self.assertEqual(os.listdir(self.directory), ["landed.aar"], "nothing was written")

    def test_an_unusable_name_falls_back_to_a_safe_one(self):
        data = b"z" * 40
        self.write(aar("../../etc/passwd", data))
        landed = bulk.extract_archive(self.path, directory=self.directory, limit=1 << 20)
        self.assertEqual(landed.name, "passwd")
        self.assertTrue(landed.path.startswith(self.directory + os.sep))


class DaemonWiring(unittest.TestCase):
    """What the daemon does with a bulk generation: fetch once, mirror, suppress repeats."""

    def setUp(self):
        from test_daemon import make_daemon                  # same harness as the daemon tests
        self.make_daemon = make_daemon

    def payload(self, data_size=308686, files=None, refused=None):
        blob = b"file:///Users/user/Downloads/stockblob-l2m.bin" + b"stockblob-l2m.bin"
        wrapper = pasteboard.parse_pasteboard_archive(_support.pasteboard_archive(
            [{"public.file-url": {"offset": 0, "size": 46,
                                  "uuid": {"NS.uuidbytes": FILE_UUID_BYTES}},
              "public.utf8-plain-text": {"offset": 46, "size": 17, "preferred": True}}],
            extra=b"", data_size=len(blob)))
        return bulk.Payload(wrapper, blob, files=files, refused=refused,
                            endpoint=("10.0.0.2", 8771))

    def test_a_fetched_generation_mirrors_and_is_not_refetched(self):
        daemon, log = self.make_daemon(scope="mac", download_dir=paths.DEFAULT_DOWNLOAD_DIR)
        peer = daemon.by_key["mac"]
        pb = file_pb()
        calls = []

        def fake_fetch(pb_, **kwargs):
            calls.append(kwargs)
            return self.payload()

        daemon.bulk_fetch = fake_fetch
        daemon._handle_pasteboard(peer, pb)
        self.assertEqual(len(calls), 1)
        self.assertEqual(daemon.mirrored_total, 1)
        self.assertEqual(daemon.counters["bulk"], 0)
        self.assertEqual(peer.last_generation["reason"], "mirror")
        self.assertTrue(peer.last_generation["mirrored"])
        self.assertTrue(peer.last_generation["bulk"], "the generation was deferred")
        self.assertEqual(daemon.clip.copies, [("public.utf8-plain-text",
                                               b"stockblob-l2m.bin")])
        self.assertIn("bulk payload fetched", log.messages("info"))
        # The regression this fixes: the same generation on the next poll is `unchanged`
        # and costs no fetch at all (it used to be another `bulk` skip every 2 s).
        daemon._handle_pasteboard(peer, pb)
        self.assertEqual(len(calls), 1, "one fetch per generation")
        self.assertEqual(daemon.counters["unchanged"], 1)
        self.assertEqual(daemon.counters["bulk"], 0)
        self.assertEqual(daemon.mirrored_total, 1)

    def test_the_fetch_log_line_names_every_landed_file_and_its_size(self):
        """The gap a user hit: `files=1` never said *where* the file went.

        A 1.6 MB HEIC copied on the Mac landed in `download_dir` and the only evidence was
        `bulk payload fetched … files=1`, so the user could not tell where their file was.
        The line is still one per fetch, still carries the payload's own `bytes=`, still
        never carries the sender's path and never the file's bytes.
        """
        with tempfile.TemporaryDirectory() as tmp:
            daemon, _log = self.make_daemon(scope="mac",
                                            download_dir=paths.DEFAULT_DOWNLOAD_DIR)
            daemon.log = logmod.Logger(path=os.path.join(tmp, "omclip.log"))
            peer = daemon.by_key["mac"]
            landed = [bulk.LandedFile("IMG_1739.HEIC", "/tmp/omclip-tests/IMG_1739.HEIC",
                                      1631561, "a" * 64),
                      bulk.LandedFile("IMG_1740.HEIC", "/tmp/omclip-tests/IMG_1740.HEIC",
                                      2048, "b" * 64)]
            daemon.bulk_fetch = lambda pb_, **kwargs: self.payload(files=landed)
            daemon._handle_pasteboard(peer, file_pb())
            daemon.log.close()
            with open(daemon.log.path) as fh:
                lines = [line for line in fh.read().splitlines()
                         if "bulk payload fetched" in line]
        self.assertEqual(len(lines), 1, "one line per fetch")
        line, = lines
        self.assertIn("files=2", line)
        self.assertIn("landed=/tmp/omclip-tests/IMG_1739.HEIC (1631561 B)", line)
        self.assertIn(", /tmp/omclip-tests/IMG_1740.HEIC (2048 B)", line)
        self.assertIn("bytes=%d" % len(self.payload().blob), line,
                      "the payload's own size, not the file's")
        self.assertIn("endpoint=10.0.0.2:8771", line)
        # The sender's path (in the payload this generation carried) and the file's bytes
        # never reach the log — the landed path is omclip's own.
        self.assertNotIn("/Users/user", line)
        self.assertNotIn("stockblob-l2m.bin", line)

    def test_a_custom_download_dir_reaches_the_fetch(self):
        daemon, _log = self.make_daemon(scope="mac", download_dir="/srv/omclip-inbox")
        peer = daemon.by_key["mac"]
        calls = []
        daemon.bulk_fetch = lambda pb_, **kwargs: (calls.append(kwargs),
                                                   self.payload())[1]
        daemon._handle_pasteboard(peer, bulk_pb())
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["download_dir"], "/srv/omclip-inbox")

    def test_a_landed_file_is_offered_as_the_file(self):
        daemon, log = self.make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        landed = bulk.LandedFile("stockblob-l2m.bin", "/tmp/omclip-tests/stockblob-l2m.bin",
                                 2000000, "c" * 64)
        daemon.bulk_fetch = lambda pb_, **kwargs: self.payload(files=[landed])
        daemon._handle_pasteboard(peer, file_pb())
        self.assertEqual(daemon.clip.copies,
                         [("public.file-url", landed.uri.encode())])
        self.assertEqual(peer.last_generation["uti"], "public.file-url")
        self.assertEqual(daemon.mirrored_total, 1)

    def test_a_file_mirror_reports_the_file_not_the_uri_bytes(self):
        """`last_bytes`, the peer's generation and the log all name the file's size.

        The offer on the clipboard is the `file://` URI — 48 bytes for this copy — which
        is what `clipboard.last_bytes` used to report, so a mirrored file read as a
        48-byte item everywhere the user looked.
        """
        daemon, log = self.make_daemon(scope="mac",
                                       download_dir=paths.DEFAULT_DOWNLOAD_DIR)
        peer = daemon.by_key["mac"]
        landed = bulk.LandedFile("IMG_1739.HEIC", "/tmp/omclip-tests/IMG_1739.HEIC",
                                 1631561, "a" * 64)
        daemon.bulk_fetch = lambda pb_, **kwargs: self.payload(files=[landed])
        daemon._handle_pasteboard(peer, file_pb())
        self.assertEqual(daemon.clip.copies, [("public.file-url", landed.uri.encode())])
        self.assertNotEqual(len(landed.uri.encode()), landed.bytes,
                            "the offer on the clipboard is the URI, never the file")
        self.assertEqual(daemon.last_uti, "public.file-url")
        self.assertEqual(daemon.last_file, {"name": "IMG_1739.HEIC",
                                            "path": "/tmp/omclip-tests/IMG_1739.HEIC",
                                            "bytes": 1631561})
        self.assertEqual(daemon.last_bytes, 1631561)
        self.assertEqual(peer.last_generation["bytes"], 1631561)
        self.assertIsNone(daemon.last_preview, "a file copy has no text to preview")
        doc = daemon.status_doc()
        self.assertEqual(doc["clipboard"]["last_file"], daemon.last_file)
        self.assertEqual(doc["clipboard"]["last_bytes"], 1631561)
        self.assertEqual(status.validate(doc), [])
        mirrored = [fields for _level, message, fields in log.lines
                    if message == "mirrored"]
        self.assertEqual(len(mirrored), 1, "one line per mirror")
        self.assertEqual(mirrored[0]["bytes"], 1631561)
        self.assertNotEqual(mirrored[0]["bytes"], len(landed.uri.encode()),
                            "the mirrored line reports the file, not the URI")
        self.assertEqual(mirrored[0]["landed"],
                         "/tmp/omclip-tests/IMG_1739.HEIC (1631561 B)")

    def test_a_file_mirror_notification_names_the_file(self):
        daemon, _log = self.make_daemon(scope="mac", notify=True,
                                        download_dir=paths.DEFAULT_DOWNLOAD_DIR)
        peer = daemon.by_key["mac"]
        landed = bulk.LandedFile("IMG_1739.HEIC", "/tmp/omclip-tests/IMG_1739.HEIC",
                                 1631561, "a" * 64)
        daemon.bulk_fetch = lambda pb_, **kwargs: self.payload(files=[landed])
        sent = []
        with unittest.mock.patch.object(daemonmod.subprocess, "run",
                                        side_effect=lambda *args, **kwargs:
                                        sent.append(list(args[0]))):
            daemon._handle_pasteboard(peer, file_pb())
        self.assertEqual(len(sent), 1)
        argv = " ".join(sent[0])
        self.assertIn("IMG_1739.HEIC", argv)
        self.assertIn("1.6 MB", argv, "the file's size, not 48 bytes")
        self.assertNotIn("48 bytes", argv)

    def test_a_failed_fetch_counts_bulk_once_and_never_touches_peer_health(self):
        daemon, log = self.make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        attempts = []

        def failing(pb_, **kwargs):
            attempts.append(1)
            raise bulk.BulkError("no _continuity._tcp instance named 97b1f7346d19 on the LAN")

        daemon.bulk_fetch = failing
        pb = bulk_pb()
        state_before = peer.state
        daemon._handle_pasteboard(peer, pb)
        self.assertEqual(daemon.counters["bulk"], 1)
        self.assertEqual(daemon.clip.copies, [])
        self.assertFalse(peer.last_generation["mirrored"])
        self.assertEqual(peer.failures, 0, "the peer session was healthy")
        self.assertEqual(peer.state, state_before, "the fetch must not move the peer state")
        lines = [f for lvl, m, f in log.lines if lvl == "info" and "bulk mode" in m]
        self.assertEqual(len(lines), 1)
        self.assertIn("no _continuity._tcp instance", lines[0]["detail"])
        # Within the retry window the generation is `unchanged`, so the counter (and the
        # network cost) does not climb at the poll cadence.
        for _ in range(4):
            daemon._handle_pasteboard(peer, pb)
        self.assertEqual(len(attempts), 1)
        self.assertEqual(daemon.counters["bulk"], 1)
        self.assertEqual(daemon.counters["unchanged"], 4)
        self.assertEqual(len([m for m in log.messages("info") if "bulk mode" in m]), 1)

    def test_an_oversize_generation_is_counted_as_oversize(self):
        daemon, _log = self.make_daemon(scope="mac", max_bytes=1024)
        peer = daemon.by_key["mac"]

        def refusing(pb_, **kwargs):
            raise bulk.Refused("pasteboard is 308686 bytes > max_bytes 1024")

        daemon.bulk_fetch = refusing
        daemon._handle_pasteboard(peer, bulk_pb(data_size=308686))
        self.assertEqual(daemon.counters["oversize"], 1)
        self.assertEqual(daemon.counters["bulk"], 0)

    def test_a_refused_file_body_is_counted_and_logged(self):
        daemon, log = self.make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        daemon.bulk_fetch = lambda pb_, **kwargs: self.payload(
            refused=[{"uuid": FILE_UUID, "error": "big.bin is 9 bytes > max_bytes 8",
                      "oversize": True}])
        daemon._handle_pasteboard(peer, file_pb())
        self.assertEqual(daemon.counters["oversize"], 1)
        self.assertEqual(daemon.mirrored_total, 0, "the pasteboard must NOT be mirrored as text")
        self.assertEqual(daemon.clip.copies, [])
        self.assertEqual(daemon.last_oversize_error, "mac: big.bin is 9 bytes > max_bytes 8")
        self.assertIn("mac: big.bin is 9 bytes > max_bytes 8", daemon.status_doc()["errors"])
        self.assertIn("bulk file exceeds max_bytes; not mirrored", log.messages("error"))

    def test_oversize_file_does_not_mirror_fallback_text_and_clears_on_next_mirror(self):
        daemon, log = self.make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        daemon.bulk_fetch = lambda pb_, **kwargs: self.payload(
            refused=[{"uuid": FILE_UUID, "error": "file.dmg is 28835840 bytes > max_bytes 8388608",
                      "oversize": True}])
        daemon._handle_pasteboard(peer, file_pb())
        self.assertEqual(daemon.counters["oversize"], 1)
        self.assertEqual(daemon.mirrored_total, 0)
        self.assertEqual(daemon.clip.copies, [])
        self.assertIn("file.dmg is 28835840 bytes > max_bytes 8388608", daemon.status_doc()["errors"][0])
        # Next generation succeeds and mirrors normal text
        daemon.bulk_fetch = lambda pb_, **kwargs: bulk.Payload(
            pasteboard.parse_pasteboard_archive(_support.pasteboard_archive(
                [{"public.utf8-plain-text": {"offset": 0, "size": 5, "preferred": True}}],
                extra=b"", data_size=5)),
            b"hello", endpoint=("127.0.0.1", 8771))
        daemon._handle_pasteboard(peer, bulk_pb(unique_id="NEXT"))
        self.assertEqual(daemon.mirrored_total, 1)
        self.assertIsNone(daemon.last_oversize_error)
        self.assertEqual(daemon.status_doc()["errors"], [])

    def test_a_retry_after_the_window_attempts_again(self):
        daemon, _log = self.make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        attempts = []

        def failing(pb_, **kwargs):
            attempts.append(1)
            raise bulk.BulkError("boom")

        daemon.bulk_fetch = failing
        pb = bulk_pb()
        daemon._handle_pasteboard(peer, pb)
        daemon._bulk_seen[peer.key]["at"] -= 3600.0        # pretend the window passed
        daemon._handle_pasteboard(peer, pb)
        self.assertEqual(len(attempts), 2)
        self.assertEqual(daemon.counters["bulk"], 2)

    def test_a_new_generation_is_fetched_even_after_a_successful_one(self):
        daemon, _log = self.make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        calls = []
        daemon.bulk_fetch = lambda pb_, **kwargs: (calls.append(1), self.payload())[1]
        daemon._handle_pasteboard(peer, file_pb())
        daemon._handle_pasteboard(peer, file_pb())
        daemon._handle_pasteboard(peer, bulk_pb(unique_id="A-DIFFERENT-GENERATION"))
        self.assertEqual(len(calls), 2)

    def test_an_unexpected_error_never_kills_the_poll(self):
        daemon, log = self.make_daemon(scope="mac")
        peer = daemon.by_key["mac"]

        def broken(pb_, **kwargs):
            raise OSError("download_dir is on a read-only filesystem")

        daemon.bulk_fetch = broken
        daemon._handle_pasteboard(peer, bulk_pb())
        self.assertEqual(daemon.counters["bulk"], 1)
        self.assertIn("bulk fetch raised OSError", log.messages("warn"))

    def test_clipboard_contents_never_reach_the_log(self):
        daemon, log = self.make_daemon(scope="mac")
        peer = daemon.by_key["mac"]
        secret = b"file:///Users/user/Documents/very-secret-plan.bin"
        wrapper = pasteboard.parse_pasteboard_archive(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": len(secret),
                                         "preferred": True}}],
            extra=b"", data_size=len(secret)))
        daemon.bulk_fetch = lambda pb_, **kwargs: bulk.Payload(wrapper, secret,
                                                              endpoint=("h", 1))
        daemon._handle_pasteboard(peer, bulk_pb())
        self.assertEqual(daemon.clip.copies, [("public.utf8-plain-text", secret)])
        for _level, message, fields in log.lines:
            self.assertNotIn("very-secret", message)
            self.assertNotIn("very-secret", json.dumps(fields, default=str))


class Resolution(unittest.TestCase):
    """How the companion stream instance is found: unicast query on AWDL, avahi on LAN."""

    def test_awdl_resolution_queries_continuity_local(self):
        saved_query = discovery.query_unicast_many
        saved_insts = discovery.instances_from_records
        queried = []
        try:
            def fake_query(iface, names, addresses, timeout=4.0):
                queried.append((iface, names, addresses))
                return {addresses[0]: ["fake-record"]}

            discovery.query_unicast_many = fake_query
            discovery.instances_from_records = lambda recs, svcs: [
                discovery.Instance(svcs[0], "59b7e9bcc17f", "somehost.local", 8771)
            ]
            endpoint = bulk.resolve({"bonjour_name": "59b7e9bcc17f"},
                                    address="fe80::6c5f:a3ff:fe96:4a3f", iface="awdl0")
            self.assertEqual(endpoint, ("fe80::6c5f:a3ff:fe96:4a3f%awdl0", 8771))
            self.assertEqual(len(queried), 1)
            self.assertEqual(queried[0][0], "awdl0")
            self.assertEqual(queried[0][1], (bulk.CONTINUITY_MDNS,))
            self.assertEqual(queried[0][2], ["fe80::6c5f:a3ff:fe96:4a3f"])
            self.assertTrue(bulk.CONTINUITY_MDNS.endswith(".local"))
        finally:
            discovery.query_unicast_many = saved_query
            discovery.instances_from_records = saved_insts

    def test_awdl_resolution_retries_once_before_giving_up(self):
        saved_query = discovery.query_unicast_many
        saved_insts = discovery.instances_from_records
        saved_sleep = time.sleep
        attempts = []
        try:
            time.sleep = lambda s: None

            def fake_query(iface, names, addrs, timeout=4.0):
                attempts.append(len(attempts))
                return {addrs[0]: ["record"]} if len(attempts) == 2 else {addrs[0]: []}

            discovery.query_unicast_many = fake_query
            discovery.instances_from_records = lambda recs, svcs: (
                [discovery.Instance(svcs[0], "59b7e9bcc17f", "host.local", 8771)]
                if recs else []
            )
            endpoint = bulk.resolve({"bonjour_name": "59b7e9bcc17f"},
                                    address="fe80::1", iface="awdl0")
            self.assertEqual(endpoint, ("fe80::1%awdl0", 8771))
            self.assertEqual(len(attempts), 2)
        finally:
            discovery.query_unicast_many = saved_query
            discovery.instances_from_records = saved_insts
            time.sleep = saved_sleep

    def test_awdl_resolution_is_case_insensitive(self):
        saved_query = discovery.query_unicast_many
        saved_insts = discovery.instances_from_records
        try:
            discovery.query_unicast_many = lambda iface, names, addrs, timeout=4.0: {
                addrs[0]: ["record"]
            }
            discovery.instances_from_records = lambda recs, svcs: [
                discovery.Instance(svcs[0], "59b7e9bcc17f", "host.local", 8771)
            ]
            endpoint = bulk.resolve({"bonjour_name": "59B7E9BCC17F"},
                                    address="fe80::1", iface="awdl0")
            self.assertEqual(endpoint, ("fe80::1%awdl0", 8771))
        finally:
            discovery.query_unicast_many = saved_query
            discovery.instances_from_records = saved_insts

    def test_awdl_resolution_raises_when_no_matching_instance(self):
        saved_query = discovery.query_unicast_many
        saved_insts = discovery.instances_from_records
        try:
            discovery.query_unicast_many = lambda iface, names, addrs, timeout=4.0: {
                addrs[0]: []
            }
            discovery.instances_from_records = lambda recs, svcs: []
            with self.assertRaises(bulk.BulkError) as caught:
                bulk.resolve({"bonjour_name": "59b7e9bcc17f"},
                             address="fe80::1", iface="awdl0")
            self.assertIn("no _continuity._tcp instance named 59b7e9bcc17f over awdl0",
                          str(caught.exception))
        finally:
            discovery.query_unicast_many = saved_query
            discovery.instances_from_records = saved_insts

    def test_lan_resolution_queries_avahi_without_domain(self):
        saved_avahi = discovery.avahi_browse
        queried = []
        try:
            def fake_browse(service, timeout=4.0):
                queried.append(service)
                return [discovery.Instance(service, "97b1f7346d19", "mac.local", 8771,
                                           address="10.0.0.2")]

            discovery.avahi_browse = fake_browse
            endpoint = bulk.resolve({"bonjour_name": "97b1f7346d19"})
            self.assertEqual(endpoint, ("10.0.0.2", 8771))
            self.assertEqual(queried, [bulk.CONTINUITY])
            self.assertFalse(bulk.CONTINUITY.endswith(".local"))
        finally:
            discovery.avahi_browse = saved_avahi

if __name__ == "__main__":
    unittest.main()
