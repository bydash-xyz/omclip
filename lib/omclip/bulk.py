"""The transfer a bulk-mode pasteboard defers to: the `_continuity._tcp` companion stream.

A pasteboard whose content exceeds ~10 KB is not inlined in the
`com.apple.handoff.payload-request` response. The response carries only a descriptor
(`extraData`: `bonjour_name`, `author_data`, `message_version`) plus a type table whose
`DataSize` is larger than those bytes, and `sharingd` serves the bytes over a TLS
connection it publishes as a `_continuity._tcp` instance (`SDStreamManager -publish`,
port 8771), authenticated on both sides with the same Apple ID identity omdrop already
uses. This module is the client side of that connection.

Wire format, verified against the live Mac (macOS 27, 2026-10-14, five fetches whose
payloads were byte-identical):

1. resolve the instance the descriptor's `bonjour_name` names and connect with mTLS
   (`keys_dir`, the omdrop client identity);
2. send `0x01 | BE32 length` followed by an **NSKeyedArchiver** archive of
   `{StreamMessageType: 0, StreamMessageVersion: 1, RequestAuthorData: …}`
   (`SDCompanionStream -sendInitialRequest`). `RequestAuthorData` must be the
   *author-data blob* — the nested property list that `extraData.author_data` carries,
   which `+[SFCompanionService serviceFromAuthorData:]` parses. Sending the parsed
   dictionary instead gets **no reply at all**: the connection is accepted and then left
   open (measured: 8 s of silence, against `CompanionStreamConnectResponse: true` 240 ms
   after the blob);
3. the reply uses the same framing with `CompanionStreamConnectResponse`; from there the
   pipe is no longer a message protocol and the holder runs **coder V2**
   (`UCStreamCoderV2`): `'C' 0x01 tag:BE32 len:BE32` messages whose bodies are
   `_UACopyPackedDataForObject` output, i.e. the 4-byte prefix `MP\\x03\\x05` followed by
   **MessagePack** (established by re-encoding the holder's own bodies byte for byte);
4. the receiver drives the exchange: tag 3 infoRequest → tag 4
   `{"data": <archive of UASharedPasteboardInfoWrapper>}`, tag 5 dataRequest → tag 6
   chunks `{"data", "packetNum", "totalNum"}` of 64 KiB that concatenate to exactly
   `DataSize`, and tag 7 fileRequest `{"supportsCompression": false, "uuid": …}` → tag 8
   chunks holding an **AppleArchive** (`AA01`) of the file's bytes.

Only V2 is implemented. `sendingCoderVersion` lives on the holder and the client cannot
ask for one; every observation of this build selects V2, so a V1 implementation would be
code that can never run here. A peer that answers with the V1 `===` push framing is
detected and refused by name rather than mis-parsed.

AppleArchive decoding covers what the holder actually sends for a file copy — one file
entry, either stored or a single raw-deflate stream — and the entry's data is located by
the record's **own** header length (`at + header`, the `u16` after `AA01`), never by
arithmetic on the archive's total size: the blob pool that carries the file's xattrs and
ACL is written *after* the data, so `total - DAT` lands `len(pool)` bytes into the file and
appends the pool — a file of exactly the declared size that is still not the file. Each
step is checked against the archive's own header, and the decoded bytes against the
record's `SH1`/`SH2` (SHA-1/SHA-256 of the data) when it carries them, so an unrecognised
or inconsistent layout is refused with its observed sizes instead of being guessed at.

Nothing here writes to the clipboard: it returns representations and landed files, and
`pasteboard.decide` still owns that decision.
"""

import hashlib
import os
import plistlib
import socket
import ssl
import struct
import tempfile
import time
import zlib

from . import discovery, paths
from .pasteboard import parse_pasteboard_archive

#: `SDStreamManager -publish` advertises this (`avahi-browse` wants it without the domain).
CONTINUITY = "_continuity._tcp"
#: Wire mDNS unicast queries (over AWDL) require the `.local` domain.
CONTINUITY_MDNS = "_continuity._tcp.local"
#: The framing `_UACopyPackedDataForObject` wraps every V2 message body in.
PACK_PREFIX = b"MP\x03\x05"
#: `UAStreamHandlerProcessor` message tags (`streams:didReadMessage:withTag:`).
TAG_INFO_REQUEST = 3
TAG_INFO_RESPONSE = 4
TAG_DATA_REQUEST = 5
TAG_DATA_RESPONSE = 6
TAG_FILE_REQUEST = 7
TAG_FILE_RESPONSE = 8
TAG_AUX_INFO = 9
TAG_HEARTBEAT = 10

CONNECT_TIMEOUT = 10.0       # TCP + TLS to the holder
READ_TIMEOUT = 5.0           # one read while the exchange is running
PEEK_TIMEOUT = 1.5           # how long to look for the holder's first V2 bytes
TOTAL_TIMEOUT = 180.0        # the whole exchange, payload included
#: A stored AppleArchive of an N-byte file is N bytes plus everything the entry carries
#: that is not its data — the header and the blob pool after the data (measured: a 466-byte
#: prefix with an 84-byte pool, and a 457-byte prefix with a 1 755-byte pool for a Photos
#: HEIC's xattrs), so this is generous while still bounding what a peer can make us write.
ARCHIVE_SLACK = 1 << 20
#: A header longer than this is not something this decoder understands.
MAX_HEADER = 64 * 1024
MAX_NAME = 255


class BulkError(Exception):
    """The transfer failed: wire, protocol, or a layout we cannot decode."""


class Refused(BulkError):
    """omclip declined the transfer itself (over `max_bytes`, no identity, …).

    Kept apart from `BulkError` so a generation that stayed unmigrated can say *why*
    without implying the peer misbehaved.
    """


class LandedFile:
    """One file whose bytes were written under the configured download directory.

    `name` is the name the archive carries (what the sender copied); `path` is where the
    bytes actually landed, which differs when that name was taken.
    """

    __slots__ = ("name", "path", "bytes", "sha256")

    def __init__(self, name, path, size, sha256):
        self.name = name
        self.path = path
        self.bytes = size
        self.sha256 = sha256

    @property
    def uri(self):
        """The `file://` URI to offer when this file is the decided representation."""
        return "file://" + self.path

    def __repr__(self):
        return "LandedFile(%s, %d bytes, %s)" % (self.name, self.bytes, self.sha256[:12])


class Payload:
    """What the companion stream delivered for one bulk generation."""

    __slots__ = ("wrapper", "blob", "data_size", "files", "refused", "endpoint")

    def __init__(self, wrapper, blob, files=None, refused=None, endpoint=None):
        self.wrapper = wrapper
        self.blob = blob
        self.data_size = len(blob)
        self.files = list(files or [])
        self.refused = list(refused or [])
        self.endpoint = endpoint

    def as_inline(self):
        """The same generation shaped like an inlined one, for `pasteboard.decide`.

        `extra_data` becomes the fetched flat buffer — the buffer the items' `offset`/
        `size` pairs index, exactly as the inline path uses `extraData` — so every
        existing representation, digest and `max_bytes` rule applies unchanged. For bulk
        mode `parse_pasteboard_archive` puts the *descriptor* in `extra_data`; that is
        never sliced.
        """
        return {"items": self.wrapper.get("items") or [],
                "data_size": self.data_size,
                "extra_data": self.blob,
                "extra_type": self.wrapper.get("extra_type"),
                "protocol_version": self.wrapper.get("protocol_version"),
                "descriptor": self.wrapper.get("descriptor"),
                "bulk": False,
                "fetched": True,
                "null_wrapper": False}

    def __repr__(self):
        return "Payload(%d bytes, %d file(s), %d refused)" % (
            self.data_size, len(self.files), len(self.refused))


# --------------------------------------------------------------- NSKeyedArchiver
class KeyedArchiver:
    """Write the archive Apple's own client sends (`-sendInitialRequest`).

    Containers are written with a `$class` stub and `NS.keys`/`NS.objects`; the numbers and
    the author-data blob are written as `NSNumber`/`NSData` objects. Apple's own archive
    stores property-list values as raw plist values instead, but its unarchiver accepts
    both — this is the shape the live Mac unpacks (it reads `StreamMessageType`, dispatches
    the request and opens the streams).
    """

    def __init__(self):
        self.objects = ["$null"]
        self._stubs = {}

    def _add(self, value):
        self.objects.append(value)
        return plistlib.UID(len(self.objects) - 1)

    def _stub(self, name, chain):
        if name not in self._stubs:
            self._stubs[name] = self._add({"$classname": name, "$classes": list(chain)})
        return self._stubs[name]

    def _value(self, value):
        if isinstance(value, bool):
            return self._number(int(value))
        if isinstance(value, int):
            return self._number(value)
        if isinstance(value, (bytes, bytearray)):
            cls = self._stub("NSData", ("NSData", "NSObject"))
            return self._add({"$class": cls, "NS.data": bytes(value)})
        if isinstance(value, str):
            return self._add(value)
        if isinstance(value, dict):
            cls = self._stub("NSDictionary", ("NSDictionary", "NSObject"))
            keys = [self._add(k) for k in value]
            vals = [self._value(v) for v in value.values()]
            return self._add({"$class": cls, "NS.keys": keys, "NS.objects": vals})
        raise TypeError("cannot archive %r" % (value,))

    def _number(self, value):
        cls = self._stub("NSNumber", ("NSNumber", "NSValue", "NSObject"))
        return self._add({"$class": cls, "NS.number": value})

    def dumps(self, root):
        top = self._value(root)
        return plistlib.dumps({"$archiver": "NSKeyedArchiver", "$version": 100000,
                               "$objects": self.objects, "$top": {"root": top}},
                              fmt=plistlib.FMT_BINARY)


def decode_archive(data):
    """Decode an NSKeyedArchiver archive into plain Python (used for the accept reply)."""
    plist = plistlib.loads(data)
    objects = plist.get("$objects")
    if objects is None:
        return plist

    def deref(value):
        if isinstance(value, plistlib.UID):
            return objects[value.data] if 0 <= value.data < len(objects) else None
        return value

    def class_of(value):
        stub = deref(value.get("$class"))
        return deref(stub.get("$classname")) if isinstance(stub, dict) else None

    def convert(value):
        value = deref(value)
        if isinstance(value, list):
            return [convert(v) for v in value]
        if isinstance(value, dict):
            name = class_of(value)
            if name in ("NSNumber", "NSDecimalNumber"):
                for key in ("NS.number", "NS.intval", "NS.dblval", "NS.boolval"):
                    if key in value:
                        return value[key]
            if name in ("NSData", "NSMutableData"):
                for key in ("NS.data", "NS.bytes"):
                    if key in value:
                        return value[key]
            if name == "NSDictionary" or (name is None and "NS.keys" in value):
                keys = [convert(k) for k in value.get("NS.keys", [])]
                vals = [convert(v) for v in value.get("NS.objects", [])]
                return dict(zip(keys, vals))
            if name == "NSArray" or (name is None and "NS.objects" in value):
                return [convert(v) for v in value.get("NS.objects", [])]
            return {k: convert(v) for k, v in value.items()
                    if k not in ("$class", "$classes", "$classname")}
        return None if value == "$null" else value

    return convert(plist.get("$top", {}).get("root"))


# ------------------------------------------------------------------ MessagePack
def _mp_decode(data, off):
    byte = data[off]
    if byte <= 0x7f:
        return byte, off + 1
    if byte >= 0xe0:
        return byte - 0x100, off + 1
    if 0x80 <= byte <= 0x8f:
        return _mp_map(data, off + 1, byte & 0x0F)
    if 0x90 <= byte <= 0x9f:
        return _mp_array(data, off + 1, byte & 0x0F)
    if 0xa0 <= byte <= 0xbf:
        size = byte & 0x1F
        return data[off + 1:off + 1 + size].decode("utf-8", "replace"), off + 1 + size
    if byte == 0xc0:
        return None, off + 1
    if byte == 0xc2:
        return False, off + 1
    if byte == 0xc3:
        return True, off + 1
    if byte in (0xc4, 0xc5, 0xc6):
        width = (1, 2, 4)[byte - 0xc4]
        size = int.from_bytes(data[off + 1:off + 1 + width], "big")
        start = off + 1 + width
        return data[start:start + size], start + size
    if byte == 0xca:
        return struct.unpack(">f", data[off + 1:off + 5])[0], off + 5
    if byte == 0xcb:
        return struct.unpack(">d", data[off + 1:off + 9])[0], off + 9
    if 0xcc <= byte <= 0xcf:
        width = (1, 2, 4, 8)[byte - 0xcc]
        return int.from_bytes(data[off + 1:off + 1 + width], "big"), off + 1 + width
    if 0xd0 <= byte <= 0xd3:
        width = (1, 2, 4, 8)[byte - 0xd0]
        return (int.from_bytes(data[off + 1:off + 1 + width], "big", signed=True),
                off + 1 + width)
    if byte in (0xd9, 0xda, 0xdb):
        width = (1, 2, 4)[byte - 0xd9]
        size = int.from_bytes(data[off + 1:off + 1 + width], "big")
        start = off + 1 + width
        return data[start:start + size].decode("utf-8", "replace"), start + size
    if byte in (0xdc, 0xdd):
        width = 2 if byte == 0xdc else 4
        return _mp_array(data, off + 1 + width,
                         int.from_bytes(data[off + 1:off + 1 + width], "big"))
    if byte in (0xde, 0xdf):
        width = 2 if byte == 0xde else 4
        return _mp_map(data, off + 1 + width,
                       int.from_bytes(data[off + 1:off + 1 + width], "big"))
    raise BulkError("packed body: unsupported MessagePack marker %#x" % byte)


def _mp_array(data, off, count):
    out = []
    for _ in range(count):
        item, off = _mp_decode(data, off)
        out.append(item)
    return out, off


def _mp_map(data, off, count):
    out = {}
    for _ in range(count):
        key, off = _mp_decode(data, off)
        value, off = _mp_decode(data, off)
        out[key] = value
    return out, off


def pack_message(obj):
    """`_UACopyPackedDataForObject`: the observed prefix followed by MessagePack."""
    return PACK_PREFIX + _mp_encode(obj)


def _mp_encode(obj):
    """MessagePack, only for what this protocol carries (the prefix is added once)."""
    if obj is None:
        return b"\xc0"
    if obj is True:
        return b"\xc3"
    if obj is False:
        return b"\xc2"
    if isinstance(obj, int):
        if 0 <= obj <= 0x7F:
            return bytes([obj])
        if -32 <= obj < 0:
            return bytes([obj & 0xFF])
        if obj <= 0xFFFFFFFF:
            return b"\xce" + struct.pack(">I", obj)
        return b"\xd3" + struct.pack(">q", obj)
    if isinstance(obj, (bytes, bytearray)):
        raw = bytes(obj)
        if len(raw) < 0x100:
            return b"\xc4" + bytes([len(raw)]) + raw
        if len(raw) < 0x10000:
            return b"\xc5" + struct.pack(">H", len(raw)) + raw
        return b"\xc6" + struct.pack(">I", len(raw)) + raw
    if isinstance(obj, str):
        raw = obj.encode()
        if len(raw) < 32:
            return bytes([0xA0 | len(raw)]) + raw
        if len(raw) < 0x100:
            return b"\xd9" + bytes([len(raw)]) + raw
        return b"\xda" + struct.pack(">H", len(raw)) + raw
    if isinstance(obj, (list, tuple)):
        return bytes([0x90 | len(obj)]) + b"".join(_mp_encode(item) for item in obj)
    if isinstance(obj, dict):
        out = bytes([0x80 | len(obj)])
        for key, value in obj.items():
            out += _mp_encode(key) + _mp_encode(value)
        return out
    raise TypeError("cannot pack %r" % (obj,))


def unpack_message(body):
    """The inverse of `pack_message`; `None` when the body is not in that form."""
    if not body.startswith(PACK_PREFIX):
        return None
    try:
        obj, consumed = _mp_decode(body, len(PACK_PREFIX))
    except (BulkError, IndexError):
        return None
    return obj if consumed == len(body) else None


def tag_message(tag, obj):
    """One V2 message: `'C' 0x01 tag:BE32 len:BE32` + the packed body."""
    body = pack_message(obj)
    return b"C\x01" + struct.pack(">II", tag, len(body)) + body


# -------------------------------------------------------------------- descriptor
def generation_key(pb):
    """A stable identity for one pasteboard *content*, used to suppress re-fetching.

    The descriptor's `unique_id` cannot serve as the identity: the sender re-mints it on
    **every** response (measured 2026-10-14 — eight announcements 3 s apart carried eight
    different `unique_id`s while the item table was byte-identical). What does persist for
    as long as the sender holds the copy is each item's `UASharedPasteboardTypeInfo` UUID
    and the type table it belongs to, so the key is the sorted (UTI, offset, size, UUID)
    list plus `DataSize`.
    """
    parts = []
    for item in pb.get("items") or []:
        for uti, info in (item.get("types") or {}).items():
            raw = (info.get("uuid") or {}).get("NS.uuidbytes")
            if isinstance(raw, (bytes, bytearray)):
                uuid = bytes(raw).hex()
            elif isinstance(raw, dict):
                uuid = raw.get("hex") or ""
            else:
                uuid = ""
            parts.append("%s|%s|%s|%s" % (uti, info.get("offset"), info.get("size"), uuid))
    digest = hashlib.sha256(("%s\x00%s" % (pb.get("data_size"), "\n".join(sorted(parts))))
                            .encode()).hexdigest()
    return digest[:16]


def descriptor_of(pb):
    """`{bonjour_name, author_data (the blob), message_version, unique_id}` of a generation.

    `pasteboard.parse_pasteboard_archive` decodes the nested `author_data` into a
    dictionary for the evidence files; the wire wants the blob, so it is read again here.
    """
    extra = pb.get("extra_data")
    if not isinstance(extra, (bytes, bytearray)):
        return None
    try:
        decoded = plistlib.loads(bytes(extra))
    except Exception:                                    # noqa: BLE001 - peer data
        return None
    if not isinstance(decoded, dict):
        return None
    author = decoded.get("author_data")
    if isinstance(author, (bytes, bytearray)):
        blob = bytes(author)
    elif isinstance(author, dict):
        blob = plistlib.dumps(author, fmt=plistlib.FMT_BINARY)
    else:
        blob = b""
    unique = ""
    try:
        unique = plistlib.loads(blob).get("unique_id") or ""
    except Exception:                                    # noqa: BLE001 - peer data
        unique = ""
    if isinstance(unique, (bytes, bytearray)):
        unique = bytes(unique).decode("utf-8", "replace")
    return {"bonjour_name": decoded.get("bonjour_name"), "author_data": blob,
            "message_version": decoded.get("message_version"), "unique_id": str(unique)}


def request_archive(descriptor):
    """The `sendInitialRequest` archive: the author-data blob, never the parsed dict."""
    return KeyedArchiver().dumps({"StreamMessageType": 0, "StreamMessageVersion": 1,
                                  "RequestAuthorData": descriptor.get("author_data") or b""})


def frame(payload):
    """`SDStreamHandler -headerWithLength:`: a 0x01 byte and a big-endian length."""
    return b"\x01" + struct.pack(">I", len(payload)) + payload


# ------------------------------------------------------------------ connection
def client_context(keys_dir):
    """The mTLS client context: omdrop's Apple ID identity, peer chain not verified.

    Verification is off because the peer's chain terminates in Apple's Application
    Integration CA, which this machine does not hold; the holder authenticates *us* the
    same way it authenticates an iPhone, and that mutual TLS is what makes the connection
    trustworthy on its side. A missing identity is a refusal, not an error: without
    `certificate.pem`/`key.pem` the peer hangs up anyway.
    """
    cert = os.path.join(keys_dir, "certificate.pem")
    key = os.path.join(keys_dir, "key.pem")
    if not (os.path.exists(cert) and os.path.exists(key)):
        raise Refused("no client identity in %s (expected certificate.pem and key.pem)"
                      % keys_dir)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    context.load_cert_chain(cert, key)
    return context


def _resolve_target(host, port, iface):
    """`(host, port)` as connect() wants it, scoping a link-local address to its interface."""
    if "%" in host:
        link, _, scope = host.partition("%")
        return (link, port, 0, socket.if_nametoindex(scope or iface or "awdl0")), socket.AF_INET6
    return (host, port), socket.AF_INET6 if ":" in host else socket.AF_INET


def connect(host, port, keys_dir, timeout=CONNECT_TIMEOUT, iface=None):
    """TCP (optionally pinned to `iface`) + TLS, every step bounded by `timeout`.

    The identity is checked first: without it the peer would hang up anyway, so a missing
    certificate must cost a refusal, not a dial.
    """
    context = client_context(keys_dir)
    target, family = _resolve_target(host, port, iface)
    raw = None
    try:
        raw = socket.socket(family, socket.SOCK_STREAM)
        raw.settimeout(timeout)
        if iface and hasattr(socket, "SO_BINDTODEVICE"):
            raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, iface.encode() + b"\0")
        raw.connect(target)
        return context.wrap_socket(raw, server_hostname=None)
    except ssl.SSLError as exc:
        if raw is not None:
            raw.close()
        raise BulkError("TLS handshake with %s:%s failed: %s" % (host, port, exc))
    except OSError as exc:
        if raw is not None:
            raw.close()
        raise BulkError("cannot reach %s:%s: %s" % (host, port, exc))


def resolve(descriptor, *, address=None, iface=None, timeout=4.0):
    """The `_continuity._tcp` instance the descriptor's `bonjour_name` names → (host, port).

    Over the LAN the instance is found with avahi (which cannot see awdl0); for an AWDL
    peer — bulk generations come from the iPhone too — the instance is asked for directly
    on its link-local address, the way `tools/bulk_probe.py` does. The peer is matched by
    the descriptor's name, so the several devices advertising the service cannot be
    confused for one another.
    """
    name = (descriptor or {}).get("bonjour_name")
    if not name:
        raise BulkError("descriptor carries no bonjour_name")
    if iface and address:
        link = address.partition("%")[0]
        for attempt in range(2):
            answers = discovery.query_unicast_many(iface, (CONTINUITY_MDNS,), [link], timeout=timeout)
            for instance in discovery.instances_from_records(answers.get(link, []), (CONTINUITY_MDNS,)):
                if instance.name.lower() == name.lower() and instance.port:
                    return "%s%%%s" % (link, iface), instance.port
            if attempt == 0:
                time.sleep(0.5)
        raise BulkError("no _continuity._tcp instance named %s over %s" % (name, iface))
    for attempt in range(2):
        for instance in discovery.avahi_browse(CONTINUITY, timeout=timeout):
            if instance.name.lower() == name.lower() and instance.port:
                return instance.address, instance.port
        if attempt == 0:
            # One pass can miss the instance: the A record for the SRV target often arrives
            # in a later packet (the same reason `Daemon._lookup_mac_instance` retries).
            time.sleep(0.5)
    raise BulkError("no _continuity._tcp instance named %s on the LAN" % name)


class Stream:
    """Bounded, framed reads over one connection.

    Every read is deadline-checked, so a silent or half-open holder costs one timeout and
    never a hung daemon. `wire` is an optional callback for protocol logging: tags and
    byte counts only, never contents.
    """

    def __init__(self, socket_obj, deadline, wire=None):
        self.socket = socket_obj
        self.deadline = deadline
        self.wire = wire
        self.buffer = bytearray()
        self.received = 0
        self.sent = 0

    def _fill(self, want, what, until=None):
        limit = self.deadline if until is None else min(self.deadline, until)
        while len(self.buffer) < want:
            left = limit - time.monotonic()
            if left <= 0:
                raise BulkError("timed out after %d bytes waiting for %s"
                                % (self.received, what))
            self.socket.settimeout(max(0.05, min(READ_TIMEOUT, left)))
            try:
                chunk = self.socket.recv(1 << 16)
            except (socket.timeout, TimeoutError, ssl.SSLWantReadError):
                continue
            except (ssl.SSLError, OSError) as exc:
                raise BulkError("%s while reading %s: %s" % (type(exc).__name__, what, exc))
            if not chunk:
                raise BulkError("holder closed the stream after %d bytes (waiting for %s)"
                                % (self.received, what))
            self.buffer.extend(chunk)
            self.received += len(chunk)
            if self.wire:
                self.wire("recv %d bytes (%s)" % (len(chunk), what))

    def exact(self, count, what):
        self._fill(count, what)
        out = bytes(self.buffer[:count])
        del self.buffer[:count]
        return out

    def peek(self, count, wait=PEEK_TIMEOUT):
        """Whatever has arrived within `wait`, up to `count` bytes (never raises)."""
        until = time.monotonic() + wait
        try:
            self._fill(1, "the first bytes", until=until)
        except BulkError:
            return b""
        return bytes(self.buffer[:count])

    def send(self, data, what):
        try:
            self.socket.sendall(data)
        except (ssl.SSLError, OSError) as exc:
            raise BulkError("%s while sending %s: %s" % (type(exc).__name__, what, exc))
        self.sent += len(data)
        if self.wire:
            self.wire("sent %d bytes (%s)" % (len(data), what))

    def message(self, what="message"):
        """One V2 message → (tag, body)."""
        header = self.exact(10, what + " header")
        if header[0:2] != b"C\x01":
            raise BulkError("expected a 'C' 0x01 message, got %s" % header[:2].hex())
        tag, length = struct.unpack(">II", header[2:10])
        body = self.exact(length, "%s tag %d body" % (what, tag)) if length else b""
        if self.wire:
            self.wire("tag %d, %d byte body" % (tag, length))
        return tag, body


# ------------------------------------------------------------------ AppleArchive
#: The fields this module reads, and the width their type character gives them. The whole
#: field block is walked, because where it ends is where the entry's data begins: a record
#: is `AA01`, a two-byte length, then fields, and the holder puts everything the entry
#: carries that is not a field — the file data first, then the xattr/ACL blob pool — after
#: it. Fields this module has no use for still have to be stepped over, so the keys and
#: the four kinds seen on the wire are modelled; an unknown key stops the walk.
_AAR_FIELDS = {b"TYP": "type", b"PAT": "path", b"SIZ": "size", b"DAT": "data",
               b"UID": "uid", b"GID": "gid", b"MOD": "mode", b"FLG": "flags",
               b"INO": "inode", b"DEV": "device", b"MTM": "mtime", b"CTM": "ctime",
               b"BTM": "btime", b"LNK": "link", b"DUZ": "duz",
               b"PRC": "parent", b"CMT": "comment", b"XAT": "xattr", b"ACL": "acl",
               b"CKS": "checksum", b"CLC": "cluster", b"SH1": "sha1", b"SH2": "sha256"}
#: The five fields whose value is a digest of the entry's data, not a number.
_AAR_DIGESTS = {b"SH1": "sha1", b"SH2": "sha256"}
#: kind character → the width its value takes. `A` is a two-byte size (`XAT`/`ACL`), `F` a
#: four-byte checksum (`CKS`), `G` a SHA-1 and `H` a SHA-256.
_AAR_FIXED = {b"1": 1, b"2": 2, b"4": 4, b"8": 8, b"T": 12, b"S": 8, b"B": 4, b"M": 8,
              b"A": 2, b"F": 4, b"G": 20, b"H": 32}


def _header_length(data, at):
    """The record's own header length: the `u16` right after `AA01` (`55 00`, `b3 00`, …).

    It counts from the magic itself — header, length, fields — so `at + header_length` is
    the first byte after the field block: the entry's data for a file (measured: 278 + 179
    = 457 on the live record), its blob pool for a directory (0 + 85 = 85). That, and not
    any arithmetic on the archive's total size, is what locates the file's bytes.
    """
    if len(data) < at + 6:
        return None
    return int.from_bytes(data[at + 4:at + 6], "little")


def _walk_entry(data, at):
    """Walk one `AA01` record's fields from `at` → (fields, end). `None` when malformed.

    Two bytes sit between the magic and the first field, so the walk is tried at the
    offsets that could hold the first key: the one that ends exactly where the record's
    own header length says it should wins, and the one that collects the most fields is
    the fallback for a header this module cannot walk all the way.
    """
    if data[at:at + 4] != b"AA01":
        return None
    wanted = _header_length(data, at)
    best = None
    for start in (at + 4, at + 5, at + 6, at + 7):
        walked = _walk_fields(data, start)
        if not walked or not walked[0]:
            continue
        fields, end = walked
        exact = wanted is not None and end == at + wanted
        if best is None or (exact, len(fields)) > (best[0], len(best[1][0])):
            best = (exact, (fields, end))
    return best[1] if best else None


def _walk_fields(data, offset):
    fields = {}
    while offset + 4 <= len(data):
        key = data[offset:offset + 3]
        if key not in _AAR_FIELDS:
            break
        kind = data[offset + 3:offset + 4]
        body = data[offset + 4:]
        width = 2 if kind == b"P" else _AAR_FIXED.get(kind)
        if width is None or len(body) < width:
            break
        if kind == b"P":
            size = int.from_bytes(body[:2], "little")
            if len(body) < 2 + size:
                break
            fields[_AAR_FIELDS[key]] = body[2:2 + size].decode("utf-8", "replace")
            offset += 4 + 2 + size
            continue
        value = body[:width]
        fields[_AAR_FIELDS[key]] = (value if key in _AAR_DIGESTS
                                    else int.from_bytes(value, "little"))
        offset += 4 + width
    return fields, offset


def archive_entries(head, *, total=None):
    """The `AA01` entries in `head` → one dict per entry, with the end of its fields.

    Records are found by their magic and walked with `_walk_entry`; an occurrence inside a
    data region is ignored when `total` is given for scale (the header cannot contain the
    whole archive). Each entry carries the record's `header` length and so `at + header`,
    the offset the entry's data starts at, beside `at`/`fields_end`.
    """
    entries = []
    start = 0
    while True:
        at = head.find(b"AA01", start)
        if at < 0:
            break
        start = at + 4
        if total is not None and at > MAX_HEADER:
            break
        walked = _walk_entry(head, at)
        if walked is None:
            continue
        fields, end = walked
        if not fields:
            continue
        header = _header_length(head, at)
        if header is None:
            continue
        entries.append(dict(fields, at=at, fields_end=end, header=header))
    return entries


def summary(head, total=None):
    """The single file entry of a landed archive → `{type, path, size, data, at, header}`."""
    entries = archive_entries(head, total=total)
    files = [entry for entry in entries
             if entry.get("type") in (ord("F"), ord("f")) and entry.get("path")]
    if not files:
        raise Refused("no file entry in the AppleArchive (saw %d record(s): %s)"
                      % (len(entries), [dict(type=chr(e["type"]) if "type" in e else None,
                                             path=e.get("path"), keys=list(e.keys())) for e in entries]))
    if len(files) > 1:
        raise Refused("AppleArchive holds %d file entries; only a single-file archive is "
                      "decoded" % len(files))
    entry = files[0]
    for needed in ("size", "data"):
        if needed not in entry:
            raise Refused("AppleArchive entry lacks its %s field" % needed)
    if entries and entry is not entries[-1]:
        raise Refused("AppleArchive file entry is not the last record")
    return entry


def _basename(path):
    name = path.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    name = "".join(ch for ch in name if ch.isprintable() and ch != os.sep)
    if name in ("", ".", ".."):
        raise Refused("archive entry has an unusable name")
    return name[:MAX_NAME]


def unique_path(directory, name):
    """A free path for `name` under `directory` — never an existing file's path."""
    stem, ext = os.path.splitext(name)
    candidate = os.path.join(directory, name)
    index = 1
    while os.path.exists(candidate):
        candidate = os.path.join(directory, "%s (%d)%s" % (stem, index, ext))
        index += 1
        if index > 999:
            raise Refused("cannot find a free name for %s" % name)
    return candidate


def _peek(path, count=MAX_HEADER):
    with open(path, "rb") as fh:
        return fh.read(count)


def extract_archive(source, *, directory, limit):
    """Decode a landed AppleArchive into one file under `directory`.

    `source` is a path, not bytes: the body is streamed to disk and decoded by streaming,
    so a multi-megabyte copy never sits in RAM. The layout supported is the one the holder
    produces for a file copy — a single file entry, stored or one raw-deflate stream —
    whose data begins **at the end of the record's own header** (`at + header`, the two
    bytes after `AA01`), *not* at the end of the archive minus the declared size: whatever
    the entry carries that is not its data (the xattr/ACL blob pool) is written *after* the
    data, so `total - DAT` starts that many bytes into the file and appends that many bytes
    of pool — same length, wrong bytes. Every claim is therefore checked before the file is
    kept: the header must be walkable and end where it says it does, the declared data must
    fit inside the archive, and the decoded bytes must match the record's own `SH1`/`SH2`
    digests. A mismatch is a refusal: a file that is not the file is worse than no file.
    """
    total = os.path.getsize(source)
    entry = summary(_peek(source), total=total)
    size, stored = entry["size"], entry["data"]
    if size > limit:
        raise Refused("%s is %d bytes > max_bytes %d" % (entry["path"], size, limit))
    start = entry["at"] + entry["header"]
    if start < entry["fields_end"] or start > total:
        raise Refused("AppleArchive header ends at %d of %d bytes, where its fields end "
                      "at %d" % (start, total, entry["fields_end"]))
    if start + stored > total:
        raise Refused("AppleArchive declares %d bytes of data at %d, past the %d byte "
                      "archive" % (stored, start, total))
    leftover = total - start - stored
    blobs = entry.get("xattr", 0) + entry.get("acl", 0)
    if leftover < blobs:
        raise Refused("only %d bytes follow the data for %d bytes of declared xattrs"
                      % (leftover, blobs))
    filename = _basename(entry["path"])
    final = unique_path(directory, filename)
    digest = hashlib.sha256()
    digest1 = hashlib.sha1()
    written = 0
    try:
        with open(source, "rb") as src, open(final, "xb") as out:
            src.seek(start)
            if stored == size:                       # stored: those bytes are the file
                remaining = stored
                while remaining:
                    block = src.read(min(1 << 16, remaining))
                    if not block:
                        break
                    remaining -= len(block)
                    out.write(block)
                    digest.update(block)
                    digest1.update(block)
                    written += len(block)
            else:                                    # one raw-deflate stream of DAT bytes
                inflater = zlib.decompressobj(-zlib.MAX_WBITS)
                remaining = stored
                while remaining:
                    block = src.read(min(1 << 16, remaining))
                    if not block:
                        break
                    remaining -= len(block)
                    pending = block
                    while pending:
                        plain = inflater.decompress(pending, 1 << 16)
                        pending = inflater.unconsumed_tail
                        out.write(plain)
                        digest.update(plain)
                        digest1.update(plain)
                        written += len(plain)
                        if written > size:
                            raise Refused("AppleArchive inflated beyond its %d byte size"
                                          % size)
                plain = inflater.flush()
                out.write(plain)
                digest.update(plain)
                digest1.update(plain)
                written += len(plain)
    except (zlib.error, OSError) as exc:
        if os.path.exists(final):
            os.unlink(final)
        raise Refused("AppleArchive data did not decode: %s" % exc)
    if written != size:
        os.unlink(final)
        raise Refused("AppleArchive declared %d bytes, decoded %d" % (size, written))
    for key, got, name in (("sha256", digest.digest(), "SHA-256"),
                           ("sha1", digest1.digest(), "SHA-1")):
        if entry.get(key) and got != entry[key]:
            os.unlink(final)
            raise Refused("AppleArchive data does not match the record's %s (%s, expected "
                          "%s)" % (name, got.hex(), entry[key].hex()))
    return LandedFile(filename, final, written, digest.hexdigest())


# --------------------------------------------------------------------- exchange
def _file_uuids(wrapper):
    """The file items' UUIDs, spelled the way the holder spells them.

    `-UUIDString` is upper case and the holder compares with `isEqualToString:`
    (`-handlePasteboardFileRequest:`), so a lower-case UUID is answered with nothing at
    all — measured: 60 s of heartbeats and no data, against 31 packets in 11 ms for the
    identical request in upper case.
    """
    out = []
    for item in wrapper.get("items") or []:
        for uti, info in (item.get("types") or {}).items():
            if uti != "public.file-url":
                continue
            # A real archive holds 16 raw bytes under `NS.uuidbytes`; the evidence files
            # render those as {"hex": …}, so both spellings are accepted here.
            raw = (info.get("uuid") or {}).get("NS.uuidbytes")
            if isinstance(raw, (bytes, bytearray)):
                hexed = bytes(raw).hex()
            elif isinstance(raw, dict) and isinstance(raw.get("hex"), str):
                hexed = raw["hex"]
            else:
                continue
            if len(hexed) < 32:
                continue
            out.append(("%s-%s-%s-%s-%s" % (hexed[0:8], hexed[8:12], hexed[12:16],
                                            hexed[16:20], hexed[20:32])).upper())
    return out


def _receive_file(stream, uuid, *, directory, limit, log=None, announce=None):
    """Stream one tag-8 file body into a `.part` file under `directory` → its path."""
    try:
        paths.ensure_dir(directory)
    except OSError as exc:
        raise Refused("cannot use download_dir %s: %s" % (directory, exc))
    handle, path = tempfile.mkstemp(prefix=".omclip-", suffix=".part", dir=directory)
    received = 0
    checked = False
    try:
        with os.fdopen(handle, "wb") as out:
            while True:
                tag, body = stream.message("file body")
                if tag in (TAG_HEARTBEAT, TAG_AUX_INFO):
                    continue
                if tag != TAG_FILE_RESPONSE:
                    raise BulkError("tag %d while receiving a file body" % tag)
                packed = unpack_message(body)
                chunk = packed.get("data") if isinstance(packed, dict) else None
                if not isinstance(chunk, bytes):
                    raise BulkError("file body is not a packed data message")
                received += len(chunk)
                if received > limit + ARCHIVE_SLACK:
                    raise Refused("file body exceeded max_bytes %d (stopped at %d bytes)"
                                  % (limit, received))
                out.write(chunk)
                if not checked and received >= 4096:
                    checked = True
                    try:
                        entry = summary(_peek(path), total=None)
                    except Refused:
                        entry = None
                    if entry and announce is not None:
                        announce(entry["path"], entry["size"])
                        if entry["size"] > limit:
                            raise Refused("%s is %d bytes > max_bytes %d"
                                          % (entry["path"], entry["size"], limit))
                if packed.get("packetNum") == packed.get("totalNum"):
                    break
    except BaseException:
        if os.path.exists(path):
            os.unlink(path)
        raise
    return path


def fetch(pb, *, keys_dir, max_bytes, download_dir, address=None, iface=None,
          connector=None, resolver=None, log=None, timeout=TOTAL_TIMEOUT,
          ready=None):
    """Fetch the payload a bulk-mode pasteboard defers to.

    Raises `Refused` when the generation is beyond `max_bytes` or uses a layout this module
    does not decode, and `BulkError` for anything the wire did. `connector` and `resolver`
    are seams: production passes neither, so `connect` and `resolve` are used; tests
    inject a loopback peer.
    """
    descriptor = descriptor_of(pb)
    if not descriptor:
        raise BulkError("bulk generation carries no usable descriptor")
    data_size = pb.get("data_size") or 0
    if not data_size:
        raise BulkError("bulk generation declares no data size")
    if data_size > max_bytes:
        raise Refused("pasteboard is %d bytes > max_bytes %d" % (data_size, max_bytes))

    host, port = (resolver or resolve)(descriptor, address=address, iface=iface)
    wire = (lambda text: log("companion stream: %s" % text)) if log else None
    socket_obj = (connector or connect)(host, port, keys_dir, CONNECT_TIMEOUT, iface)
    stream = Stream(socket_obj, time.monotonic() + timeout, wire=wire)
    if ready is not None:
        ready(host, port, stream)
    try:
        stream.send(frame(request_archive(descriptor)), "initial request")
        return _exchange(stream, data_size, host, port, download_dir=download_dir,
                         max_bytes=max_bytes, log=log)
    finally:
        try:
            socket_obj.close()
        except OSError:
            pass


def _exchange(stream, data_size, host, port, *, download_dir, max_bytes, log=None):
    head = stream.exact(5, "accept header")
    if head[0] != 1:
        raise BulkError("accept frame type %#x is not 1" % head[0])
    (length,) = struct.unpack(">I", head[1:5])
    reply = decode_archive(stream.exact(length, "accept body"))
    if not isinstance(reply, dict) or not reply.get("CompanionStreamConnectResponse"):
        raise BulkError("holder refused the stream request (%s)" % (reply,))
    opener = stream.peek(3)
    if opener[:3] == b"===":
        raise BulkError("holder chose coder V1 (the '===' push framing); only coder V2 is "
                        "implemented and no build here has ever selected V1")

    stream.send(tag_message(TAG_INFO_REQUEST, 0), "infoRequest")
    wrapper = None
    blob = bytearray()
    while True:
        tag, body = stream.message()
        if tag == TAG_HEARTBEAT:
            continue
        packed = unpack_message(body)
        if tag == TAG_AUX_INFO:
            if log and isinstance(packed, dict):
                log("holder announced totalSize=%s" % packed.get("totalSize"))
        elif tag == TAG_INFO_RESPONSE:
            data = packed.get("data") if isinstance(packed, dict) else None
            if not isinstance(data, bytes):
                raise BulkError("holder has no pasteboard to send for this generation "
                                "(empty info response)")
            wrapper = parse_pasteboard_archive(data)
            declared = wrapper.get("data_size") or data_size
            if declared > max_bytes:
                raise Refused("pasteboard is %d bytes > max_bytes %d" % (declared, max_bytes))
            stream.send(tag_message(TAG_DATA_REQUEST, 0), "dataRequest")
        elif tag == TAG_DATA_RESPONSE:
            chunk = packed.get("data") if isinstance(packed, dict) else None
            if not isinstance(chunk, bytes):
                raise BulkError("data message without bytes")
            if len(blob) + len(chunk) > max_bytes:
                raise Refused("pasteboard exceeded max_bytes %d while arriving" % max_bytes)
            blob.extend(chunk)
            if packed.get("packetNum") == packed.get("totalNum"):
                break
        elif tag == TAG_FILE_RESPONSE:
            raise BulkError("file body arrived before the pasteboard data")
        elif log:
            log("ignoring tag %d" % tag)

    if wrapper is None:
        raise BulkError("holder sent no pasteboard info")
    size = wrapper.get("data_size")
    if size and len(blob) != size:
        raise BulkError("received %d bytes for a declared %d byte pasteboard"
                        % (len(blob), size))

    files, refused = [], []
    if download_dir:
        for uuid in _file_uuids(wrapper):
            try:
                stream.send(tag_message(TAG_FILE_REQUEST,
                                        {"supportsCompression": False, "uuid": uuid}),
                            "fileRequest")
                announced = (lambda name, size_: log("file body: %s is %d bytes"
                                                     % (name, size_))) if log else None
                path = _receive_file(stream, uuid, directory=download_dir,
                                     limit=max_bytes, log=log, announce=announced)
                try:
                    landed = extract_archive(path, directory=download_dir, limit=max_bytes)
                finally:
                    if os.path.exists(path):
                        os.unlink(path)
                files.append(landed)
                if log:
                    log("landed %s, %d bytes, sha256 %s"
                        % (landed.path, landed.bytes, landed.sha256[:12]))
            except Refused as exc:
                # A body that is too big, or an archive we do not decode, must not cost
                # the rest of the generation: the pasteboard itself is still returned.
                refused.append({"uuid": uuid, "error": str(exc),
                                "oversize": "> max_bytes" in str(exc)})
                if log:
                    log("file body refused: %s" % exc)
                break                     # stream state is only known up to here
            except BulkError as exc:
                refused.append({"uuid": uuid, "error": str(exc), "oversize": False})
                if log:
                    log("file body failed: %s" % exc)
                break
    return Payload(wrapper, bytes(blob), files, refused, endpoint=(host, port))
