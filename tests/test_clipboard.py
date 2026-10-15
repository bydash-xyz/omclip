"""What `Clipboard.copy` asks wl-copy for, without needing a Wayland session.

The offer shape is the contract that makes universal paste work: plain text must reach
both the clipboard selection (non-terminal windows paste `CTRL + V`) and PRIMARY
(terminal windows paste `SHIFT + Insert`), while images and rich text stay on the
clipboard selection alone.
"""

import unittest
from unittest import mock

import _support  # noqa: F401  (sets sys.path for the omclip package)
from omclip import clipboard as clipmod


class Recorder:
    def __init__(self):
        self.lines = []

    def _add(self, level, message, **fields):
        self.lines.append((level, message, fields))
        return True

    error = lambda self, m, **f: self._add("error", m, **f)      # noqa: E731
    warn = lambda self, m, **f: self._add("warn", m, **f)        # noqa: E731
    info = lambda self, m, **f: self._add("info", m, **f)        # noqa: E731
    debug = lambda self, m, **f: self._add("debug", m, **f)      # noqa: E731

    def messages(self, level=None):
        return [m for lvl, m, _f in self.lines if level is None or lvl == level]


def copy_with_stub(uti, *, fails=(), data=b"payload", log=None, binary="/usr/bin/wl-copy"):
    """Call `Clipboard.copy` with wl-copy stubbed. Returns (mime, [argv, ...]).

    `fails` lists 1-based offer numbers that should raise, so a test can fail the
    clipboard offer without failing the PRIMARY one, or the other way round.
    """
    calls = []
    fail_at = set(fails)

    def fake_run(cmd, **_kwargs):
        calls.append(list(cmd))
        if len(calls) in fail_at:
            raise OSError("stub wl-copy failure")
        return mock.Mock(returncode=0)

    clip = clipmod.Clipboard(log=log)
    with mock.patch.object(clipmod, "tool", return_value=binary), \
            mock.patch.object(clipmod.subprocess, "run", side_effect=fake_run):
        mime = clip.copy(data, uti)
    return mime, calls


class OfferShape(unittest.TestCase):
    def test_plain_text_offers_clipboard_then_primary(self):
        mime, calls = copy_with_stub("public.utf8-plain-text")
        self.assertEqual(mime, "text/plain")
        self.assertEqual(calls, [["/usr/bin/wl-copy", "--type", "text/plain"],
                                 ["/usr/bin/wl-copy", "--type", "text/plain", "--primary"]])

    def test_public_text_and_utf16_are_plain_text_too(self):
        for uti in ("public.text", "public.utf16-plain-text"):
            with self.subTest(uti=uti):
                mime, calls = copy_with_stub(uti)
                self.assertEqual(mime, "text/plain")
                self.assertTrue(calls[1][-1] == "--primary", calls)

    def test_rich_text_and_images_stay_on_the_clipboard(self):
        for uti, mime in (("public.html", "text/html"), ("public.rtf", "text/rtf"),
                          ("public.file-url", "text/uri-list"), ("public.png", "image/png"),
                          ("public.tiff", "image/tiff")):
            with self.subTest(uti=uti):
                got, calls = copy_with_stub(uti, data=b"\x89PNG")
                self.assertEqual(got, mime)
                self.assertEqual(len(calls), 1, "non-plain-text must not touch PRIMARY")
                self.assertEqual(calls[0], ["/usr/bin/wl-copy", "--type", mime])

    def test_unknown_uti_falls_back_to_text_plain(self):
        mime, calls = copy_with_stub(None)
        self.assertEqual(mime, "text/plain")
        self.assertEqual(len(calls), 1)

    def test_plain_text_keeps_its_explicit_type(self):
        # `--type text/plain` must stay: without it wl-copy sniffs the payload, and a
        # UTF-16 pasteboard (public.utf16-plain-text) is offered as
        # application/octet-stream, which no application pastes as text. For UTF-8 text
        # the explicit type still advertises the standard text targets.
        _mime, calls = copy_with_stub("public.utf8-plain-text")
        self.assertEqual(calls[0][:3], ["/usr/bin/wl-copy", "--type", "text/plain"])


class Failures(unittest.TestCase):
    def test_missing_wl_copy_mirrors_nothing(self):
        mime, calls = copy_with_stub("public.utf8-plain-text", binary=None)
        self.assertIsNone(mime)
        self.assertEqual(calls, [])

    def test_clipboard_failure_returns_none_and_skips_primary(self):
        log = Recorder()
        mime, calls = copy_with_stub("public.utf8-plain-text", fails=(1,), log=log)
        self.assertIsNone(mime, "a failed clipboard offer must not claim a mirror")
        self.assertEqual(len(calls), 1)
        self.assertTrue(any("wl-copy failed" in m for m in log.messages("error")), log.lines)

    def test_primary_failure_still_counts_as_mirrored(self):
        log = Recorder()
        mime, calls = copy_with_stub("public.utf8-plain-text", fails=(2,), log=log)
        self.assertEqual(mime, "text/plain")
        self.assertEqual(len(calls), 2)
        self.assertTrue(any("--primary" in m for m in log.messages("warn")), log.lines)
        self.assertEqual(log.messages("error"), [])


if __name__ == "__main__":
    unittest.main()
