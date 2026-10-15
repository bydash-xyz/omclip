"""The device's own Rapport/IDS identity, read in place from `identity_dir`.

`rapport_identity.json` is the Air's RPIdentity as an OPACK blob
(`edSK`/`edPK`/`dIRK`), `rapport_ids.json` holds the `_idsID` announced in
`_systemInfo`. Without the latter, every `com.apple.handoff.payload-request` is
refused with `IDS device not found` (measured) — so a missing `_idsID` is a hard
failure, not a warning.

These files are read, never copied: they are credential material and must not enter
omclip's tree or any commit. Extraction is out of scope: see the README.
"""

import base64
import json
import os

from .crypto import opack_decode


class Identity:
    __slots__ = ("ed_sk", "ed_pk", "ids_id", "dirk", "directory")

    def __init__(self, ed_sk, ed_pk, ids_id, dirk=None, directory=None):
        self.ed_sk = ed_sk
        self.ed_pk = ed_pk
        self.ids_id = ids_id
        self.dirk = dirk
        self.directory = directory

    @property
    def ed_pk_hex(self):
        return self.ed_pk.hex()

    def __repr__(self):
        return "Identity(edPK=%s…, idsID=%s)" % (self.ed_pk.hex()[:8], self.ids_id)


IDENTITY_NAME = "rapport_identity.json"
IDS_NAME = "rapport_ids.json"

REFRESH_HINT = 're-extract from your own macOS install; see "Credentials" in the omclip README'


def load(directory):
    """Load the identity → (Identity, error). Exactly one is None. Never raises."""
    ident_path = os.path.join(directory, IDENTITY_NAME)
    ids_path = os.path.join(directory, IDS_NAME)
    try:
        items = json.load(open(ident_path, "r", encoding="utf-8"))
    except FileNotFoundError:
        return None, "%s not found (%s)" % (ident_path, REFRESH_HINT)
    except (OSError, ValueError) as exc:
        return None, "cannot read %s: %s" % (ident_path, exc)
    ed_sk = ed_pk = dirk = None
    for item in items if isinstance(items, list) else []:
        raw = item.get("data")
        if not raw:
            continue
        try:
            decoded, _ = opack_decode(base64.b64decode(raw))
        except Exception:                          # noqa: BLE001 - skip undecodable items
            continue
        if isinstance(decoded, dict) and "edSK" in decoded:
            ed_sk, ed_pk, dirk = decoded["edSK"], decoded.get("edPK"), decoded.get("dIRK")
            break
    if ed_sk is None or ed_pk is None:
        return None, "no edSK/edPK in %s (%s)" % (ident_path, REFRESH_HINT)
    try:
        with open(ids_path, "r", encoding="utf-8") as fh:
            ids_id = json.load(fh).get("idsDeviceID")
    except FileNotFoundError:
        return None, "%s not found: without the _idsID every payload request is refused " \
                     "(%s)" % (ids_path, REFRESH_HINT)
    except (OSError, ValueError) as exc:
        return None, "cannot read %s: %s" % (ids_path, exc)
    if not ids_id:
        return None, "no idsDeviceID in %s (%s)" % (ids_path, REFRESH_HINT)
    return Identity(ed_sk, ed_pk, ids_id, dirk, directory), None
