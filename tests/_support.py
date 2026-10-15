"""Shared test helpers: path setup and fixture builders. Offline only."""

import os
import plistlib
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
if os.path.join(ROOT, "lib") not in sys.path:
    sys.path.insert(0, os.path.join(ROOT, "lib"))
if HERE not in sys.path:
    sys.path.insert(0, HERE)


# --------------------------------------------------------------------------
# Hermetic radio: no test may start/stop bluetooth.service, flip rfkill or run omdrop.
# Measured 2026-10-13: the omdrop-window tests reached the real `systemctl start
# bluetooth.service` + `rfkill unblock` through `_ensure_bluetooth` (passwordless polkit
# here), leaving the radio up above the machine's idle baseline. Tests that need a
# command's output stub `run`/`_run` themselves and restore this fake afterwards.
# --------------------------------------------------------------------------

from omclip import bluetooth as _bluetooth, omdrop as _omdrop   # noqa: E402

SYSTEM_CALLS = []


def _no_system_run(cmd, timeout=2.0):
    SYSTEM_CALLS.append(list(cmd))
    return 1, ""


def _no_omdrop_run(args, timeout=None):
    SYSTEM_CALLS.append(["omdrop"] + list(args))
    return 127, "", "omdrop is not run in tests"


_bluetooth.run = _no_system_run
_omdrop._run = _no_omdrop_run

# ...nor read this machine's live AWDL peer table or write the real phone memory.
import tempfile as _tempfile                                             # noqa: E402

from omclip import discovery as _discovery, paths as _paths              # noqa: E402

_SCRATCH = _tempfile.mkdtemp(prefix="omclip-tests-")
_discovery.AWDL_PEERS_FILE = os.path.join(_SCRATCH, "no-awdl-peers.json")
_paths.PHONE_FILE = os.path.join(_SCRATCH, "phone.json")
_paths.BULK_DIR = os.path.join(_SCRATCH, "bulk")
# ...nor write a received file body into the real ~/Downloads: the default has to point
# somewhere the test process owns, because `make_daemon` uses real settings.
_paths.DEFAULT_DOWNLOAD_DIR = os.path.join(_SCRATCH, "downloads")


# --------------------------------------------------------------------------
# UASharedPasteboardInfoWrapper fixtures (NSKeyedArchiver, as the peer sends it)
# --------------------------------------------------------------------------

def _type_info(info):
    out = {"UASharedPasteboardTypeInfoOffsetKey": info.get("offset", 0),
           "UASharedPasteboardTypeInfoSizeKey": info.get("size", 0),
           "UASharedPasteboardTypeInfoPrefRepKey": 1 if info.get("preferred") else 0}
    if info.get("data_file") is not None:
        out["UASharedPasteboardTypeInfoDataFileKey"] = info["data_file"]
    if info.get("uuid") is not None:
        # A file item carries its `NSUUID` next to the type info; the real archive holds
        # 16 raw bytes under `NS.uuidbytes`.
        out["UASharedPasteboardTypeInfoUUIDKey"] = info["uuid"]
    return out


def pasteboard_archive(items=None, extra=b"", data_size=None, extra_type=0,
                       protocol_version=0, null_root=False):
    """Build an `rActPayload`-shaped archive.

    `items` is a list of {uti: {"offset", "size", "preferred", "data_file"}}; each list
    entry becomes one `UASharedPasteboardItemInfo` object and the per-type infos are
    plain dicts in `$objects` (no class stubs), which is how the converter reads them.
    The wrapper points at the info dict by UID, exactly like the real archive.
    """
    if null_root:
        # An empty peer pasteboard: $top.root -> "$null".
        return plistlib.dumps({"$version": 100000, "$archiver": "NSKeyedArchiver",
                               "$top": {"root": "$null"},
                               "$objects": ["$null"]}, fmt=plistlib.FMT_BINARY)
    objects = ["$null", None, None]
    item_uids = []
    for item in items or []:
        types_map = {}
        for uti, info in item.items():
            types_map[uti] = plistlib.UID(len(objects))
            objects.append(_type_info(info))
        item_uids.append(plistlib.UID(len(objects)))
        objects.append({"UASharedPasteboardItemInfoTypesKey": types_map})
    objects[2] = {"UASharedPasteboardInfoItemsKey": item_uids,
                  "UASharedPasteboardInfoDataSizeKey": (len(extra) if data_size is None
                                                        else data_size)}
    objects[1] = {"UASharedPasteboardInfoWrapperPBInfoKey": plistlib.UID(2),
                  "UASharedPasteboardInfoWrapperExtraDataKey": bytes(extra),
                  "UASharedPasteboardInfoWrapperExtraTypeKey": extra_type,
                  "UASharedPasteboardInfoWrapperProtocolVersionKey": protocol_version}
    # Binary format: the real archive is binary and only FMT_BINARY carries UIDs.
    return plistlib.dumps({"$version": 100000, "$archiver": "NSKeyedArchiver",
                           "$top": {"root": plistlib.UID(1)},
                           "$objects": objects}, fmt=plistlib.FMT_BINARY)


def inline_text(text, uti="public.utf8-plain-text", preferred=True):
    """The common case: one text representation, fully inlined."""
    data = text.encode()
    return pasteboard_archive([{uti: {"offset": 0, "size": len(data), "preferred": preferred}}],
                              extra=data)


def bulk_descriptor(unique_id="UID-1", manager_id="MGR", client_id="CLI", bonjour="host.local"):
    """The `author_data` descriptor bulk mode puts in `extraData` (~324 bytes)."""
    return plistlib.dumps({
        "author_data": plistlib.dumps({"unique_id": unique_id, "manager_id": manager_id,
                                       "client_id": client_id}, fmt=plistlib.FMT_BINARY),
        "bonjour_name": bonjour,
        "message_version": 1,
    }, fmt=plistlib.FMT_BINARY)
