"""Decode `_c.rActPayload` and decide what (if anything) to mirror.

The peer returns an `NSKeyedArchiver` `UASharedPasteboardInfoWrapper`:

    root: {$top.root -> UID -> wrapper}
    wrapper: UASharedPasteboardInfoWrapperPBInfoKey -> UASharedPasteboardInfo
              .UASharedPasteboardInfoItemsKey -> [UASharedPasteboardItemInfo]
                 .UASharedPasteboardItemInfoTypesKey -> {uti: UASharedPasteboardTypeInfo}
                    .OffsetKey / .SizeKey / .PrefRepKey / .DataFileKey
             UASharedPasteboardInfoWrapperExtraDataKey -> bytes  <- representations

`plistlib` handles the `UID`s; `$objects`/`$class` are resolved by hand.

Mode facts measured live (2026-10-13, macOS + iOS):

* A pasteboard whose whole content exceeds ~10 KB comes back in **bulk mode**:
  `extraData` is a 324-byte `{author_data{unique_id,manager_id,client_id}, bonjour_name,
  message_version}` descriptor, per-type offset/size address a buffer served elsewhere,
  and **no bytes are inlined**. Slicing the descriptor as if it were payload produces
  garbage, so it must never be done.
* The tell is `DataSize > len(extraData)` — NOT `ExtraTypeKey`, because iOS sends
  `ExtraTypeKey = 2` for rich-but-fully-inlined pasteboards.
* An empty peer pasteboard arrives as a null wrapper (`$top.root -> "$null"`).
"""

import hashlib
import plistlib
import re

_PB_KEYS = {
    "UASharedPasteboardInfoWrapperErrorKey": "error",
    "UASharedPasteboardInfoWrapperExtraDataKey": "extra_data",
    "UASharedPasteboardInfoWrapperPBInfoKey": "pb_info",
    "UASharedPasteboardInfoWrapperProtocolVersionKey": "protocol_version",
    "UASharedPasteboardInfoWrapperExtraTypeKey": "extra_type",
    "UASharedPasteboardInfoItemsKey": "items",
    "UASharedPasteboardInfoDataFileKey": "data_file",
    "UASharedPasteboardInfoDataSizeKey": "data_size",
    "UASharedPasteboardInfoDataPathKey": "data_path",
    "UASharedPasteboardInfoExtensionKey": "extension",
    "UASharedPasteboardItemInfoTypesKey": "types",
    "UASharedPasteboardTypeInfoOffsetKey": "offset",
    "UASharedPasteboardTypeInfoSizeKey": "size",
    "UASharedPasteboardTypeInfoTypeKey": "type",
    "UASharedPasteboardTypeInfoPrefRepKey": "preferred",
    "UASharedPasteboardTypeInfoDataFileKey": "data_file",
    "UASharedPasteboardTypeInfoFileContentType": "file_content_type",
    "UASharedPasteboardTypeInfoTypeHintKey": "type_hint",
    "UASharedPasteboardTypeInfoUUIDKey": "uuid",
    "UASharedPasteboardTypeInfoIndex": "index",
}

#: What a mirrored item is offered to Wayland as. `wl-copy` serves one explicit MIME
#: type per offer, and for a text type it also advertises the standard text targets
#: (`text/plain`, `text/plain;charset=utf-8`, `TEXT`, `STRING`, `UTF8_STRING`), so the
#: type below is what an application asks for first rather than the only offer.
#: Binary types (images) get exactly the one type listed here.
UTI_MIME = {
    "public.utf8-plain-text": "text/plain",
    "public.utf16-plain-text": "text/plain",
    "public.text": "text/plain",
    "public.html": "text/html",
    "public.rtf": "text/rtf",
    "public.png": "image/png",
    "public.tiff": "image/tiff",
    "public.jpeg": "image/jpeg",
    "public.file-url": "text/uri-list",
}

#: Preference order for the representation to mirror (preferred flag wins first).
UTI_PREFERENCE = ("public.utf8-plain-text", "public.text", "public.html", "public.png",
                  "public.tiff", "public.rtf", "public.jpeg", "public.file-url")

#: UTIs whose content may be summarised into `clipboard.last_preview`. Never logged.
TEXT_UTIS = ("public.utf8-plain-text", "public.text", "public.utf16-plain-text")

PREVIEW_LIMIT = 160


class Decision:
    """Outcome of one pasteboard generation: mirror it, or say why not."""

    __slots__ = ("reason", "uti", "data", "digest", "bulk", "data_size", "detail")

    def __init__(self, reason, uti=None, data=None, digest=None, bulk=False,
                 data_size=None, detail=None):
        self.reason = reason
        self.uti = uti
        self.data = data
        self.digest = digest
        self.bulk = bulk
        self.data_size = data_size
        self.detail = detail

    @property
    def mirror(self):
        return self.reason == "mirror"

    def __repr__(self):
        return ("Decision(%s, uti=%s, bytes=%s, digest=%s, bulk=%s, detail=%s)"
                % (self.reason, self.uti, len(self.data) if self.data is not None else None,
                   (self.digest or "")[:12], self.bulk, self.detail))


def parse_pasteboard_archive(blob):
    """Decode `_c.rActPayload` into {"error", "protocol_version", "extra_data", "items", ...}.

    `items` is a list of {"types": {uti: {"offset", "size", "preferred", ...}}}.
    Representation bytes live in `extra_data[offset:offset+size]`.
    """
    archive = plistlib.loads(blob)
    objs = archive.get("$objects")

    def deref(value):
        return objs[value.data] if isinstance(value, plistlib.UID) else value

    def class_name(value):
        stub = deref(deref(value["$class"]))
        return deref(stub.get("$classname")) if isinstance(stub, dict) else None

    def convert(value):
        value = deref(value)
        if isinstance(value, list):
            # A keyed-archive array usually holds UIDs pointing into $objects; the
            # reference client only dereferenced dict values, which breaks on a UID
            # element, so lists are converted element-wise here.
            return [convert(x) for x in value]
        if isinstance(value, dict):
            name = class_name(value) if "$class" in value else None
            if name == "NSArray":
                return [convert(x) for x in value.get("NS.objects", [])]
            if name == "NSDictionary":
                keys = [convert(k) for k in value.get("NS.keys", [])]
                vals = [convert(v) for v in value.get("NS.objects", [])]
                return dict(zip(keys, vals))
            body = {_PB_KEYS.get(k, k): convert(v) for k, v in value.items() if k != "$class"}
            return body if name is None else {"__class__": name, **body}
        if isinstance(value, str) and value == "$null":
            return None
        return value

    wrapper = convert(archive["$top"]["root"])
    if not isinstance(wrapper, dict):
        # Empty peer pasteboard: $top.root is "$null".
        return {"error": None, "protocol_version": None, "extra_data": None,
                "extra_type": None, "data_size": None, "bulk": False,
                "descriptor": None, "items": [], "null_wrapper": True}
    pb_info = wrapper.get("pb_info") or {}
    items = [{"types": item.get("types") or {}} for item in (pb_info.get("items") or [])]
    extra = wrapper.get("extra_data")
    data_size = pb_info.get("data_size")
    bulk = bool(extra is not None and data_size and data_size > len(extra))
    return {"error": wrapper.get("error"),
            "protocol_version": wrapper.get("protocol_version"),
            "extra_data": extra,
            "extra_type": wrapper.get("extra_type"),
            "data_size": data_size,
            "bulk": bulk,
            "descriptor": _author_descriptor(extra) if bulk else None,
            "items": items,
            "null_wrapper": False}


def _jsonable(value):
    """Plist values → JSON (bytes as hex, dates as ISO), for evidence files."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (bytes, bytearray)):
        return {"hex": bytes(value).hex()}
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def bulk_evidence(pb):
    """What a bulk-mode generation tells us about the transfer it defers to: the decoded
    descriptor (`bonjour_name`, `author_data`), the type table and the raw descriptor."""
    return {"data_size": pb.get("data_size"),
            "extra_type": pb.get("extra_type"),
            "protocol_version": pb.get("protocol_version"),
            "descriptor": _jsonable(pb.get("descriptor")),
            "items": _jsonable(pb.get("items") or []),
            "extra_data_hex": bytes(pb.get("extra_data") or b"").hex()}


def _author_descriptor(extra):
    """Bulk-mode `extra_data`: {author_data{uuid,manager,client}, bonjour_name, …}."""
    try:
        data = plistlib.loads(bytes(extra))
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    nested = data.get("author_data")
    if isinstance(nested, (bytes, bytearray)):
        try:
            data["author_data"] = plistlib.loads(bytes(nested))
        except Exception:
            pass
    return data


def representation(pb, uti):
    """Raw bytes of one representation, or None when they are not inlined."""
    extra = pb.get("extra_data")
    if extra is None or pb.get("bulk"):
        return None
    for item in pb.get("items", []):
        info = (item.get("types") or {}).get(uti)
        if info and info.get("data_file") is None:
            end = info.get("offset", 0) + info.get("size", 0)
            if end > len(extra):
                return None          # wrong mode for this item; never invent bytes
            return bytes(extra)[info.get("offset", 0):end]
    return None


def best_representation(pb, prefer=None, skip=()):
    """Pick the representation to mirror: preferred flag first, then `prefer` order."""
    order = list(prefer or UTI_PREFERENCE)
    found = []
    for item in pb.get("items", []):
        for uti, info in (item.get("types") or {}).items():
            if uti in skip or info.get("data_file") is not None:
                continue
            rank = order.index(uti) if uti in order else len(order)
            found.append((not info.get("preferred", False), rank, uti))
    for _, _, uti in sorted(found):
        data = representation(pb, uti)
        if data is not None:
            return uti, data
    return None, None


def has_file_item(pb):
    """True when the type table carries a file reference (`public.file-url`)."""
    for item in pb.get("items", []):
        if "public.file-url" in (item.get("types") or {}):
            return True
    return False


def digest_of(uti, data):
    """sha256 over `uti + b"\\x00" + representation bytes`.

    Deliberately NOT over `extra_data`: bulk-mode generations have no representation,
    so the digest must be a property of the item we would mirror.
    """
    h = hashlib.sha256()
    h.update((uti or "").encode())
    h.update(b"\x00")
    h.update(data or b"")
    return h.hexdigest()


_WS = re.compile(r"[ \t\r]+")


def preview_of(uti, data, limit=PREVIEW_LIMIT):
    """Human preview of a text item (never logged, capped, control chars stripped).

    Only text UTIs are previewed: an image or a file URL has no useful preview and
    must not be dumped anywhere.
    """
    if data is None or uti not in TEXT_UTIS:
        return None
    text = data.decode("utf-8", "replace")
    # One line only: every control character (newlines included) becomes a space.
    text = "".join(ch if ch >= " " else " " for ch in text)
    text = _WS.sub(" ", text).strip()
    if len(text) > limit:
        return text[:limit - 1] + "…"
    return text or None


def decide(pb, *, prev_digest=None, written=(), local=None, max_bytes=256 * 1024 * 1024,
           file_uri=None):
    """Decide what to do with one fetched pasteboard generation.

    Reasons, in the order they are tested (each maps to a `clipboard.skipped` counter):

      * `empty`      — null wrapper / items but nothing to inline: never touch the clipboard
      * `bulk`       — `DataSize > len(extraData)`: bytes are deferred to a transfer we
                       do not implement (the descriptor must never be sliced)
      * `nodata`     — no representable item inlined (e.g. data_file-backed, or pbtypes)
      * `unchanged`  — same digest as the last generation seen from this peer
      * `local_echo` — the digest is one we wrote ourselves, or the local selection is
                       already byte-identical: mirroring would clobber the user's copy
                       with its own content and re-announce it
      * `oversize`   — beyond `max_bytes`; a 4 GB machine must not swallow an enormous copy
      * `mirror`     — copy it

    `written` is an iterable of digests omclip has put on the clipboard; `local` is
    `(mime, bytes)` of the current local selection or None. `file_uri` is the local
    `file://` URI of a body `bulk.py` landed: when the generation is a file copy, the file
    is what the user wants to paste, and the sender's own path is not offered because it
    does not exist on this machine.
    """
    if pb is None:
        return Decision("nodata", detail="no rActPayload in the response")
    if pb.get("bulk"):
        return Decision("bulk", bulk=True, data_size=pb.get("data_size"),
                        detail="DataSize %s > extraData %s bytes: bytes deferred to an "
                               "unimplemented transfer" % (
                                   pb.get("data_size"),
                                   len(pb["extra_data"]) if pb.get("extra_data") else 0))
    if not pb.get("items") and pb.get("extra_data") is None:
        return Decision("empty", detail="null UASharedPasteboardInfoWrapper")
    uti, data = best_representation(pb)
    if file_uri and has_file_item(pb):
        uti, data = "public.file-url", file_uri.encode()
    if data is None:
        return Decision("nodata", detail="no inlined representation")
    digest = digest_of(uti, data)
    if prev_digest and digest == prev_digest:
        return Decision("unchanged", uti=uti, digest=digest, data=data)
    if digest in set(written):
        return Decision("local_echo", uti=uti, digest=digest, data=data,
                        detail="digest was written by omclip")
    if local is not None and local[1] == data:
        return Decision("local_echo", uti=uti, digest=digest, data=data,
                        detail="local selection is byte-identical")
    if len(data) > max_bytes:
        return Decision("oversize", uti=uti, digest=digest, data=None, data_size=len(data),
                        detail="%d bytes > max_bytes %d" % (len(data), max_bytes))
    return Decision("mirror", uti=uti, digest=digest, data=data, data_size=len(data))
