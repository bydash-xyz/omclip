"""Credential presence and expiry, reported and never repaired.

Two bundles matter:

* `~/.omdrop/keys/{certificate.pem,key.pem,validation_record.cms}` — the AirDrop
  Apple-ID identity; the certificate + validation record expire **2026-11-12**
  (`ValidAsDuration` 30 days) and peers then see the Air as `window: self-signed`
  instead of `window: disk`.
* `<identity_dir>/{rapport_identity.json,rapport_ids.json}` — the Pair-Verify Ed25519
  identity and the `_idsID` announced in `_systemInfo`; without the latter every
  payload request is refused with `IDS device not found`.

omclip reads these files in place; it never copies them into its own tree and never
touches the keychain on any Apple device. Expiry comes from `openssl x509 -enddate`
(parsed here) unless `cryptography` is already importable, in which case it is used
without becoming a dependency.
"""

import os
import plistlib
import re
import sys
from datetime import datetime, timedelta, timezone

from .discovery import run
from .identity import REFRESH_HINT

WARN_DAYS = 14

#: (file, kind, expiry source). Three different things expire on three different clocks, and
#: conflating them makes the panel's warning useless: the certificate is a genuine Apple cert
#: (notBefore/notAfter ~13 months), while the *validation record* is what tells peers we are a
#: validated same-account device and carries its own `ValidAsOf` + `SuggestValidDuration`
#: (30 days measured 2026-10-13).
AIRDROP_FILES = (("certificate.pem", "airdrop-certificate", "x509"),
                 ("key.pem", "airdrop-key", None),
                 ("validation_record.cms", "airdrop-validation-record", "cms"))
IDENTITY_FILES = (("rapport_identity.json", "rapport-identity"),
                  ("rapport_ids.json", "rapport-ids"))

ENDDATE_RE = re.compile(r"notAfter=(.+)")


class Credential:
    __slots__ = ("file", "kind", "not_after", "days_left", "status", "detail")

    def __init__(self, file, kind, not_after=None, days_left=None, status="unknown",
                 detail=None):
        self.file = file
        self.kind = kind
        self.not_after = not_after
        self.days_left = days_left
        self.status = status
        self.detail = detail

    def as_dict(self):
        return {"file": self.file, "kind": self.kind, "not_after": self.not_after,
                "days_left": self.days_left, "status": self.status,
                "detail": self.detail}


# --------------------------------------------------------------------------
# pure helpers (unit-tested)
# --------------------------------------------------------------------------

def classify(present, days_left):
    """`ok` / `warn` (≤ 14 days) / `expired` / `missing` / `unknown`."""
    if not present:
        return "missing"
    if days_left is None:
        return "unknown"
    if days_left < 0:
        return "expired"
    if days_left <= WARN_DAYS:
        return "warn"
    return "ok"


def parse_enddate(text):
    """`openssl x509 -enddate -noout` output → ISO-8601 UTC string (or None)."""
    match = ENDDATE_RE.search(text or "")
    if not match:
        return None
    raw = match.group(1).strip()
    raw = re.sub(r"\s+(GMT|UTC)$", "", raw)
    for fmt in ("%b %d %H:%M:%S %Y", "%Y-%m-%d %H:%M:%S"):
        try:
            stamp = datetime.strptime(raw, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
        return stamp.isoformat().replace("+00:00", "Z")
    return None


def days_left(iso, now=None):
    """Whole days until `iso` (negative when already past)."""
    if not iso:
        return None
    try:
        stamp = datetime.fromisoformat(iso.replace("Z", "+00:00"))
    except ValueError:
        return None
    now = now or datetime.now(timezone.utc)
    return int((stamp - now).total_seconds() // 86400)


# --------------------------------------------------------------------------
# live checks
# --------------------------------------------------------------------------

def record_expiry_from_plist(data):
    """The AirDrop validation record's own expiry: `ValidAsOf + SuggestValidDuration`.

    The `validation_record.cms` is a CMS SignedData whose content is an XML plist with
    `ValidAsOf` (a UTC datetime) and `SuggestValidDuration` (seconds). That sum — not the
    certificate's `notAfter` — is what decides whether peers still see this device as a
    validated same-account device. Returns ISO-8601 UTC or None; the rest of the record
    (validated e-mail/phone hashes, altDSID) is deliberately neither read nor reported.
    """
    try:
        doc = plistlib.loads(data)
    except Exception:                          # noqa: BLE001 - not a plist, not our problem
        return None
    if not isinstance(doc, dict):
        return None
    valid_as_of = doc.get("ValidAsOf")
    duration = doc.get("SuggestValidDuration")
    if not isinstance(valid_as_of, datetime) or not isinstance(duration, (int, float)):
        return None
    if valid_as_of.tzinfo is None:
        valid_as_of = valid_as_of.replace(tzinfo=timezone.utc)   # Apple writes UTC
    stamp = valid_as_of + timedelta(seconds=float(duration))
    return stamp.isoformat().replace("+00:00", "Z")


def record_expiry(path):
    """Unwrap the CMS (`openssl cms -verify -noverify`) and read the record's own expiry."""
    if not os.path.exists(path):
        return None
    rc, out = run(["openssl", "cms", "-verify", "-noverify", "-inform", "DER", "-in", path],
                  timeout=3.0)
    if rc != 0 or not out:
        return None
    return record_expiry_from_plist(out.encode("utf-8", "replace"))


def _x509_enddate(path):
    """Certificate notAfter as ISO-8601 UTC, or None.

    `openssl` is the primary path: it is a 16 ms subprocess that costs no resident
    memory, while importing `cryptography` pulls in a ~8 MB Rust extension — real money
    on a 4 GB machine for one date. `cryptography` is only used when something else in
    this process already imported it ("only if already importable").
    """
    if not os.path.exists(path):
        return None
    if "cryptography.x509" in sys.modules:
        try:
            from cryptography import x509              # noqa: PLC0415
            with open(path, "rb") as fh:
                cert = x509.load_pem_x509_certificate(fh.read())
            stamp = cert.not_valid_after_utc if hasattr(cert, "not_valid_after_utc") \
                else cert.not_valid_after.replace(tzinfo=timezone.utc)
            return stamp.isoformat().replace("+00:00", "Z")
        except Exception:                          # noqa: BLE001 - fall back to openssl
            pass
    rc, out = run(["openssl", "x509", "-enddate", "-noout", "-in", path], timeout=3.0)
    return parse_enddate(out) if rc == 0 else None


def check(keys_dir, identity_dir, now=None):
    """All credential entries for `status.credentials` (never raises)."""
    now = now or datetime.now(timezone.utc)
    out = []
    for name, kind, source in AIRDROP_FILES:
        path = os.path.join(keys_dir, name)
        present = os.path.exists(path)
        if not present:
            iso = left = None
            status = "missing"
            detail = "missing; install the AirDrop credentials (%s)" % REFRESH_HINT
        elif source == "x509":
            iso = _x509_enddate(path)
            left = days_left(iso, now) if iso else None
            status = classify(True, left)
            detail = ("could not read the certificate expiry; is `openssl` installed?"
                      if iso is None else None)
        elif source == "cms":
            iso = record_expiry(path)
            left = days_left(iso, now) if iso else None
            status = classify(True, left)
            detail = ("could not read the record's ValidAsOf/SuggestValidDuration; re-extract "
                      "it (%s)" % REFRESH_HINT if iso is None else None)
        else:
            iso = left = None
            status = "ok"
            detail = None
        out.append(Credential(_pretty(path), kind, iso, left, status, detail))
    for name, kind in IDENTITY_FILES:
        path = os.path.join(identity_dir, name)
        present = os.path.exists(path)
        status = "ok" if present else "missing"
        detail = None if present else ("missing; re-extract on the macOS install (%s)" % REFRESH_HINT)
        out.append(Credential(_pretty(path), kind, None, None, status, detail))
    return out


def _pretty(path):
    home = os.path.expanduser("~")
    return "~" + path[len(home):] if path.startswith(home + os.sep) else path


def worst(credentials):
    """The most alarming status present (for `doctor` / the daemon's startup warn)."""
    order = ["expired", "missing", "warn", "unknown", "ok"]
    for status in order:
        if any(c.status == status for c in credentials):
            return status
    return "ok"
