"""Credential expiry classification (report, never repair)."""

import os
import plistlib
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

import _support  # noqa: F401
from omclip import credentials

NOW = datetime(2026, 10, 13, 12, 0, tzinfo=timezone.utc)

#: Real output shape from `openssl x509 -enddate -noout`.
OPENSSL_OUTPUT = "notAfter=Nov 12 01:52:55 2027 GMT\n"


class Classify(unittest.TestCase):
    def test_missing(self):
        self.assertEqual(credentials.classify(False, None), "missing")
        self.assertEqual(credentials.classify(False, 100), "missing")

    def test_ok(self):
        self.assertEqual(credentials.classify(True, 30), "ok")
        self.assertEqual(credentials.classify(True, 15), "ok")

    def test_warn_at_14_days_or_less(self):
        self.assertEqual(credentials.classify(True, 14), "warn")
        self.assertEqual(credentials.classify(True, 1), "warn")
        self.assertEqual(credentials.classify(True, 0), "warn")

    def test_expired(self):
        self.assertEqual(credentials.classify(True, -1), "expired")
        self.assertEqual(credentials.classify(True, -400), "expired")

    def test_unknown(self):
        self.assertEqual(credentials.classify(True, None), "unknown")


class ParseEnddate(unittest.TestCase):
    def test_real_openssl_line(self):
        self.assertEqual(credentials.parse_enddate(OPENSSL_OUTPUT), "2027-11-12T01:52:55Z")

    def test_utc_suffix_and_iso_form(self):
        self.assertEqual(credentials.parse_enddate("notAfter=Nov 12 00:00:00 2026 UTC"),
                         "2026-11-12T00:00:00Z")
        self.assertEqual(credentials.parse_enddate("notAfter=2026-11-12 00:00:00"),
                         "2026-11-12T00:00:00Z")

    def test_junk(self):
        self.assertIsNone(credentials.parse_enddate(""))
        self.assertIsNone(credentials.parse_enddate("notAfter="))
        self.assertIsNone(credentials.parse_enddate("garbage"))


class DaysLeft(unittest.TestCase):
    def test_known_dates(self):
        self.assertEqual(credentials.days_left("2026-10-13T12:00:00Z", NOW), 0)
        self.assertEqual(credentials.days_left("2026-10-14T12:00:00Z", NOW), 1)
        self.assertEqual(credentials.days_left("2026-10-12T12:00:00Z", NOW), -1)
        self.assertEqual(credentials.days_left("2027-11-12T01:52:55Z", NOW), 394)

    def test_bad_input(self):
        self.assertIsNone(credentials.days_left(None, NOW))
        self.assertIsNone(credentials.days_left("nonsense", NOW))


class Check(unittest.TestCase):
    def test_missing_tree(self):
        with tempfile.TemporaryDirectory() as tmp:
            entries = credentials.check(os.path.join(tmp, "keys"),
                                        os.path.join(tmp, "identity"), NOW)
        kinds = [entry.kind for entry in entries]
        self.assertEqual(kinds, ["airdrop-certificate", "airdrop-key",
                                 "airdrop-validation-record", "rapport-identity",
                                 "rapport-ids"])
        self.assertTrue(all(entry.status == "missing" for entry in entries))
        self.assertTrue(all(entry.detail for entry in entries))

    def test_present_presence_only_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = os.path.join(tmp, "keys")
            ident = os.path.join(tmp, "identity")
            os.makedirs(keys)
            os.makedirs(ident)
            for name in ("key.pem", "validation_record.cms"):
                with open(os.path.join(keys, name), "w") as fh:
                    fh.write("x")
            for name in ("rapport_identity.json", "rapport_ids.json"):
                with open(os.path.join(ident, name), "w") as fh:
                    fh.write("{}")
            entries = {entry.kind: entry for entry in credentials.check(keys, ident, NOW)}
        self.assertEqual(entries["airdrop-key"].status, "ok")
        self.assertIsNone(entries["airdrop-key"].days_left)
        # A record that cannot be unwrapped is `unknown`, never silently `ok`: its expiry is
        # what decides whether peers still see a validated same-account device.
        self.assertEqual(entries["airdrop-validation-record"].status, "unknown")
        self.assertIn("ValidAsOf", entries["airdrop-validation-record"].detail)
        self.assertEqual(entries["rapport-identity"].status, "ok")
        self.assertEqual(entries["rapport-ids"].status, "ok")
        # certificate.pem is absent → missing, with a pointer at the refresh path.
        self.assertEqual(entries["airdrop-certificate"].status, "missing")
        self.assertIn("README", entries["airdrop-certificate"].detail)

    def test_unreadable_certificate_is_unknown_not_a_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            keys = os.path.join(tmp, "keys")
            os.makedirs(keys)
            with open(os.path.join(keys, "certificate.pem"), "w") as fh:
                fh.write("not a certificate")
            entries = {entry.kind: entry for entry in credentials.check(keys, tmp, NOW)}
        self.assertEqual(entries["airdrop-certificate"].status, "unknown")
        self.assertIn("could not read", entries["airdrop-certificate"].detail)

    def test_credentials_are_read_in_place(self):
        # Nothing is copied: the reported path is the source path.
        with tempfile.TemporaryDirectory() as tmp:
            entries = credentials.check(os.path.join(tmp, "k"), os.path.join(tmp, "i"), NOW)
        for entry in entries:
            self.assertTrue(entry.file.endswith((".pem", ".cms", ".json")))

    def test_worst_status_ordering(self):
        def entry(status):
            return credentials.Credential("f", "k", status=status)
        self.assertEqual(credentials.worst([entry("ok"), entry("warn")]), "warn")
        self.assertEqual(credentials.worst([entry("warn"), entry("expired")]), "expired")
        self.assertEqual(credentials.worst([entry("ok"), entry("unknown")]), "unknown")
        self.assertEqual(credentials.worst([entry("ok")]), "ok")


class ValidationRecordExpiry(unittest.TestCase):
    """The record's own clock: ValidAsOf + SuggestValidDuration (measured: 30 days)."""

    @staticmethod
    def record(valid_as_of=None, duration=2592000):
        doc = {"Version": 2, "altDsID": "000000-00-00000000-0000-0000-0000-000000000000",
               "ValidAsOf": valid_as_of or datetime(2026, 10, 13, 2, 4, 37),
               "ValidatedEmailHashes": ["deadbeef"]}
        if duration is not None:
            doc["SuggestValidDuration"] = duration
        return plistlib.dumps(doc, fmt=plistlib.FMT_XML)

    def test_real_shaped_record(self):
        self.assertEqual(credentials.record_expiry_from_plist(self.record()),
                         "2026-11-12T02:04:37Z")

    def test_timezone_aware_valid_as_of(self):
        aware = datetime(2026, 10, 13, 2, 4, 37, tzinfo=timezone.utc)
        self.assertEqual(credentials.record_expiry_from_plist(self.record(aware)),
                         "2026-11-12T02:04:37Z")

    def test_missing_duration_is_unknown_not_invented(self):
        self.assertIsNone(credentials.record_expiry_from_plist(self.record(duration=None)))

    def test_junk_and_non_dict(self):
        self.assertIsNone(credentials.record_expiry_from_plist(b"not a plist"))
        self.assertIsNone(credentials.record_expiry_from_plist(b""))
        self.assertIsNone(credentials.record_expiry_from_plist(
            plistlib.dumps([1, 2, 3], fmt=plistlib.FMT_XML)))

    def test_missing_file(self):
        self.assertIsNone(credentials.record_expiry("/nonexistent/validation_record.cms"))

    def test_record_and_certificate_are_separate_clocks(self):
        # The whole point: the certificate is good for ~13 months while the record is what
        # expires in 30 days, so the two must never share a date.
        cert = credentials.parse_enddate("notAfter=Nov 12 01:52:55 2027 GMT")
        record = credentials.record_expiry_from_plist(self.record())
        self.assertEqual((cert, record), ("2027-11-12T01:52:55Z", "2026-11-12T02:04:37Z"))
        self.assertNotEqual(credentials.days_left(cert, NOW),
                            credentials.days_left(record, NOW))


class ExpiryWiring(unittest.TestCase):
    """`check()` must classify each file from its own expiry source."""

    def _entries(self, cert_days, record_days):
        saved = (credentials._x509_enddate, credentials.record_expiry)
        stamp = lambda days: (NOW + timedelta(days=days)).isoformat().replace("+00:00", "Z")
        credentials._x509_enddate = lambda path: stamp(cert_days)
        credentials.record_expiry = lambda path: (stamp(record_days)
                                                 if record_days is not None else None)
        try:
            with tempfile.TemporaryDirectory() as tmp:
                keys = os.path.join(tmp, "keys")
                os.makedirs(keys)
                for name in ("certificate.pem", "key.pem", "validation_record.cms"):
                    with open(os.path.join(keys, name), "w") as fh:
                        fh.write("x")
                entries = {entry.kind: entry for entry in credentials.check(keys, tmp, NOW)}
        finally:
            credentials._x509_enddate, credentials.record_expiry = saved
        return entries

    def test_certificate_ok_but_record_about_to_expire(self):
        entries = self._entries(cert_days=394, record_days=10)
        self.assertEqual(entries["airdrop-certificate"].status, "ok")
        self.assertEqual(entries["airdrop-certificate"].days_left, 394)
        self.assertEqual(entries["airdrop-validation-record"].status, "warn")
        self.assertEqual(entries["airdrop-validation-record"].days_left, 10)

    def test_expired_record(self):
        entries = self._entries(cert_days=394, record_days=-1)
        self.assertEqual(entries["airdrop-validation-record"].status, "expired")
        self.assertEqual(entries["airdrop-certificate"].status, "ok")

    def test_unreadable_record_is_unknown_with_a_hint(self):
        entries = self._entries(cert_days=394, record_days=None)
        record = entries["airdrop-validation-record"]
        self.assertEqual(record.status, "unknown")
        self.assertIn("README", record.detail)


class ExpiryWindowIsReal(unittest.TestCase):
    def test_installed_certificate_within_a_fortnight_of_warning(self):
        # Sanity: with the documented refresh cycle the classifier flips when it should.
        soon = (NOW + timedelta(days=13)).isoformat().replace("+00:00", "Z")
        self.assertEqual(credentials.classify(True, credentials.days_left(soon, NOW)), "warn")
        past = (NOW - timedelta(days=1)).isoformat().replace("+00:00", "Z")
        self.assertEqual(credentials.classify(True, credentials.days_left(past, NOW)), "expired")


if __name__ == "__main__":
    unittest.main()
