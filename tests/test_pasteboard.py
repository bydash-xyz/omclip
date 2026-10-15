"""Archive decoding and the skip/mirror decision for every reason.

The reasons are the contract of requirement 3-7 in the brief; each one is tested with a
fixture shaped like the real archive:

  mirror, unchanged, bulk, empty, oversize, local_echo (both halves), nodata.
"""

import unittest

import _support
from omclip import pasteboard

TEXT = "Braun : Designed to Keep"
ARCHIVE = _support.inline_text(TEXT)
DATA = TEXT.encode()


def parse(archive):
    return pasteboard.parse_pasteboard_archive(archive)


class Parsing(unittest.TestCase):
    def test_inline_text(self):
        pb = parse(ARCHIVE)
        self.assertFalse(pb["bulk"])
        self.assertEqual(pb["error"], None)
        self.assertEqual(pb["items"][0]["types"]["public.utf8-plain-text"]["size"], len(DATA))
        self.assertEqual(pb["extra_data"], DATA)
        self.assertEqual(pasteboard.representation(pb, "public.utf8-plain-text"), DATA)
        self.assertEqual(pasteboard.best_representation(pb), ("public.utf8-plain-text", DATA))

    def test_null_root_is_empty(self):
        pb = parse(_support.pasteboard_archive(null_root=True))
        self.assertTrue(pb["null_wrapper"])
        self.assertEqual(pb["items"], [])
        self.assertIsNone(pb["extra_data"])

    def test_items_array_of_uids_is_dereferenced(self):
        # The real archive stores the item array as UIDs into $objects.
        pb = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 5}},
             {"public.html": {"offset": 5, "size": 4}}], extra=b"hellotext"))
        self.assertEqual(len(pb["items"]), 2)
        self.assertEqual(pasteboard.representation(pb, "public.utf8-plain-text"), b"hello")
        self.assertEqual(pasteboard.representation(pb, "public.html"), b"text")

    def test_preferred_flag_wins_over_preference_order(self):
        pb = parse(_support.pasteboard_archive(
            [{"public.html": {"offset": 0, "size": 8, "preferred": True},
              "public.utf8-plain-text": {"offset": 8, "size": 5, "preferred": False}}],
            extra=b"<b>helloplain"))
        self.assertEqual(pasteboard.best_representation(pb),
                         ("public.html", b"<b>hello"))
        # Without the preferred flag the preference order would pick the text.
        pb = parse(_support.pasteboard_archive(
            [{"public.html": {"offset": 0, "size": 8},
              "public.utf8-plain-text": {"offset": 8, "size": 5}}],
            extra=b"<b>helloplain"))
        self.assertEqual(pasteboard.best_representation(pb),
                         ("public.utf8-plain-text", b"plain"))

    def test_preference_order_without_preferred_flag(self):
        pb = parse(_support.pasteboard_archive(
            [{"public.html": {"offset": 0, "size": 4},
              "public.utf8-plain-text": {"offset": 4, "size": 5}}], extra=b"xxxxhello"))
        self.assertEqual(pasteboard.best_representation(pb)[0], "public.utf8-plain-text")

    def test_out_of_range_slice_never_invents_bytes(self):
        pb = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 4096}}], extra=b"short"))
        self.assertIsNone(pasteboard.representation(pb, "public.utf8-plain-text"))

    def test_bulk_detection_by_data_size_not_extra_type(self):
        # iOS sends ExtraTypeKey 2 for rich-but-fully-inlined pasteboards: not a bulk tell.
        inlined = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 5}}], extra=b"hello",
            extra_type=2))
        self.assertFalse(inlined["bulk"])
        descriptor = _support.bulk_descriptor()
        bulk = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 200000}}],
            extra=descriptor, data_size=200000, extra_type=1))
        self.assertTrue(bulk["bulk"])
        self.assertEqual(bulk["data_size"], 200000)
        self.assertEqual(bulk["descriptor"]["bonjour_name"], "host.local")
        self.assertEqual(bulk["descriptor"]["message_version"], 1)

    def test_data_file_backed_type_has_no_inline_bytes(self):
        pb = parse(_support.pasteboard_archive(
            [{"public.png": {"offset": 0, "size": 1024, "data_file": "file.bin"}}], extra=b""))
        self.assertIsNone(pasteboard.representation(pb, "public.png"))
        self.assertEqual(pasteboard.best_representation(pb), (None, None))


class Decisions(unittest.TestCase):
    def decide(self, **kwargs):
        return pasteboard.decide(parse(ARCHIVE), **kwargs)

    def test_mirror(self):
        decision = self.decide()
        self.assertEqual(decision.reason, "mirror")
        self.assertTrue(decision.mirror)
        self.assertEqual(decision.data, DATA)
        self.assertEqual(decision.uti, "public.utf8-plain-text")
        self.assertEqual(decision.digest, pasteboard.digest_of(decision.uti, DATA))

    def test_unchanged(self):
        digest = pasteboard.digest_of("public.utf8-plain-text", DATA)
        self.assertEqual(self.decide(prev_digest=digest).reason, "unchanged")

    def test_bulk_is_never_sliced(self):
        descriptor = _support.bulk_descriptor()
        pb = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 5000}}],
            extra=descriptor, data_size=5000))
        decision = pasteboard.decide(pb)
        self.assertEqual(decision.reason, "bulk")
        self.assertTrue(decision.bulk)
        self.assertIsNone(decision.data)
        self.assertEqual(decision.data_size, 5000)
        self.assertIn("5000", decision.detail)
        # The descriptor is reported, never sliced into a fake payload.
        self.assertEqual(decision.uti, None)
        self.assertEqual(pb["extra_data"], descriptor)

    def test_empty(self):
        self.assertEqual(pasteboard.decide(parse(_support.pasteboard_archive(null_root=True))
                                          ).reason, "empty")

    def test_no_act_payload_is_nodata(self):
        self.assertEqual(pasteboard.decide(None).reason, "nodata")

    def test_metadata_only_is_nodata(self):
        # `pbtypes` returns an item table without extraData.
        pb = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 5}}], extra=b""))
        self.assertEqual(pasteboard.decide(pb).reason, "nodata")

    def test_oversize(self):
        big = "x" * 4096
        pb = parse(_support.inline_text(big))
        decision = pasteboard.decide(pb, max_bytes=1024)
        self.assertEqual(decision.reason, "oversize")
        self.assertIsNone(decision.data)
        self.assertEqual(pasteboard.decide(pb, max_bytes=len(big)).reason, "mirror")

    def test_local_echo_by_digest_we_wrote(self):
        digest = pasteboard.digest_of("public.utf8-plain-text", DATA)
        decision = pasteboard.decide(parse(ARCHIVE), written=[digest])
        self.assertEqual(decision.reason, "local_echo")
        self.assertIn("omclip", decision.detail)

    def test_local_echo_by_identical_selection(self):
        decision = pasteboard.decide(parse(ARCHIVE), local=("text/plain", DATA))
        self.assertEqual(decision.reason, "local_echo")
        self.assertIn("identical", decision.detail)

    def test_local_selection_that_differs_is_not_an_echo(self):
        self.assertEqual(pasteboard.decide(parse(ARCHIVE),
                                           local=("text/plain", b"something else")).reason,
                         "mirror")

    def test_unchanged_wins_over_local_echo(self):
        digest = pasteboard.digest_of("public.utf8-plain-text", DATA)
        self.assertEqual(pasteboard.decide(parse(ARCHIVE), prev_digest=digest,
                                           written=[digest]).reason, "unchanged")

    def test_bulk_wins_over_unchanged(self):
        pb = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 5000}}],
            extra=_support.bulk_descriptor(), data_size=5000))
        self.assertEqual(pasteboard.decide(pb, prev_digest="deadbeef").reason, "bulk")


class Digests(unittest.TestCase):
    def test_digest_covers_uti_and_bytes(self):
        first = pasteboard.digest_of("public.utf8-plain-text", b"x")
        self.assertNotEqual(first, pasteboard.digest_of("public.html", b"x"))
        self.assertNotEqual(first, pasteboard.digest_of("public.utf8-plain-text", b"y"))
        self.assertEqual(len(first), 64)

    def test_digest_is_not_taken_over_extra_data(self):
        # The brief: digest over `uti + b"\x00" + representation`, never over extraData
        # (which is only the bulk descriptor). Same representation, different envelope
        # sizes → identical digest.
        pb_a = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 5}}], extra=b"hello"))
        pb_b = parse(_support.pasteboard_archive(
            [{"public.utf8-plain-text": {"offset": 0, "size": 5}}], extra=b"hello",
            extra_type=2, protocol_version=3))
        uti_a, data_a = pasteboard.best_representation(pb_a)
        uti_b, data_b = pasteboard.best_representation(pb_b)
        self.assertEqual(pasteboard.digest_of(uti_a, data_a),
                         pasteboard.digest_of(uti_b, data_b))


class Previews(unittest.TestCase):
    def test_text_is_capped_at_160_chars(self):
        preview = pasteboard.preview_of("public.utf8-plain-text", b"y" * 500)
        self.assertEqual(len(preview), 160)
        self.assertTrue(preview.endswith("…"))

    def test_control_characters_are_replaced_and_collapsed(self):
        preview = pasteboard.preview_of("public.utf8-plain-text", b"a\x00b\t\tc\n\nd")
        self.assertEqual(preview, "a b c d")

    def test_non_text_utis_are_never_previewed(self):
        self.assertIsNone(pasteboard.preview_of("public.png", b"\x89PNG"))
        self.assertIsNone(pasteboard.preview_of("public.file-url", b"file:///x"))
        self.assertIsNone(pasteboard.preview_of("public.utf8-plain-text", b""))

    def test_preview_is_what_would_be_shown(self):
        self.assertEqual(pasteboard.preview_of("public.utf8-plain-text", TEXT.encode()), TEXT)


if __name__ == "__main__":
    unittest.main()
