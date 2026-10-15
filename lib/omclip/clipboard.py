"""Wayland clipboard access (wl-clipboard) with echo suppression state.

`wl-copy` forks a daemon that owns the selection, so it must be started with a fresh
session and /dev/null stdio: it has to outlive the command, and it must not hold our
pipes open.

One `wl-copy` invocation fills one selection, so a plain-text mirror offers twice:
CLIPBOARD (what non-terminal apps paste) and PRIMARY (what `Shift + Insert` pastes in
terminal windows, which is how universal paste reaches them).

Echo suppression has two halves, both required:

* a small LRU of digests omclip itself put on the clipboard (nothing else in
  `clipboard.skipped.local_echo` distinguishes "we wrote this" from "the user copied
  the same thing"), and
* a best-effort read of the current local selection (`wl-paste --no-newline --type
  MIME`), size-capped so a gigantic local selection cannot cost us memory.

Keeping the read best-effort matters: no compositor, no `wl-paste`, or no selection
must never stop the mirror — it only disables one of the two echo checks.
"""

import os
import shutil
import subprocess
from collections import OrderedDict

from .pasteboard import UTI_MIME, TEXT_UTIS

#: How many of our own writes to remember (digest → nothing; order is the LRU).
WRITTEN_MAX = 32
#: Do not read a local selection larger than this just to compare it.
DEFAULT_MAX_READ = 4 * 1024 * 1024


def tool(name):
    for candidate in ("/usr/bin/" + name, "/usr/local/bin/" + name):
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return shutil.which(name)


def wayland_available():
    """True when WAYLAND_DISPLAY resolves to a socket in XDG_RUNTIME_DIR."""
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        return False
    display = os.environ.get("WAYLAND_DISPLAY")
    if display:
        if os.path.isabs(display):
            return os.path.exists(display)
        return os.path.exists(os.path.join(runtime, display))
    return any(name.startswith("wayland-") and not name.endswith(".lock")
               for name in _listdir(runtime))


def _listdir(path):
    try:
        return os.listdir(path)
    except OSError:
        return []


def adopt_wayland_env():
    """Set WAYLAND_DISPLAY from the runtime dir when a service did not import it.

    A systemd user unit on this machine gets `XDG_RUNTIME_DIR` but not always
    `WAYLAND_DISPLAY`; `wl-copy` needs both.
    """
    if os.environ.get("WAYLAND_DISPLAY"):
        return os.environ["WAYLAND_DISPLAY"]
    runtime = os.environ.get("XDG_RUNTIME_DIR")
    if not runtime:
        return None
    for name in sorted(_listdir(runtime)):
        if name.startswith("wayland-") and not name.endswith(".lock"):
            os.environ["WAYLAND_DISPLAY"] = name
            return name
    return None


class Clipboard:
    """wl-copy/wl-paste wrapper + the "we wrote this" digest set."""

    def __init__(self, max_read=DEFAULT_MAX_READ, log=None):
        self.max_read = max_read
        self.log = log
        self._written = OrderedDict()

    # -- reading -----------------------------------------------------------

    def list_types(self):
        binary = tool("wl-paste")
        if binary is None:
            return []
        try:
            proc = subprocess.run([binary, "--list-types"], capture_output=True, timeout=3.0,
                                  check=False)
        except (OSError, subprocess.SubprocessError):
            return []
        if proc.returncode != 0:
            return []
        return [line.strip() for line in proc.stdout.decode().splitlines() if line.strip()]

    def read_local(self, mime=None):
        """(mime, bytes) of the local selection, or None. Size-capped, best-effort."""
        binary = tool("wl-paste")
        if binary is None:
            return None
        types = self.list_types()
        if not types:
            return None
        chosen = mime if mime in types else None
        if chosen is None:
            for candidate in ("text/plain", "text/plain;charset=utf-8", "text/html"):
                if candidate in types:
                    chosen = candidate
                    break
        if chosen is None:
            chosen = types[0]
        try:
            proc = subprocess.Popen([binary, "--no-newline", "--type", chosen],
                                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        except (OSError, subprocess.SubprocessError):
            return None
        try:
            data = proc.stdout.read(self.max_read + 1)
        except OSError:
            data = b""
        finally:
            # Kill first, then close: a pipe left open here is a descriptor leak that
            # the daemon would accumulate one poll at a time.
            try:
                proc.kill()
            except OSError:
                pass
            try:
                proc.stdout.close()
            except (OSError, ValueError):
                pass
            try:
                proc.wait(timeout=1)
            except subprocess.SubprocessError:
                pass
        if len(data) > self.max_read:
            return None                        # too big to compare cheaply
        return chosen, data

    # -- writing -----------------------------------------------------------

    def copy(self, data, uti):
        """Put bytes on the Wayland clipboard. Returns the MIME type used, or None.

        Plain text also goes to the PRIMARY selection. Universal paste (``SUPER + V``)
        sends ``SHIFT + Insert`` in terminal windows, and ``Shift+Insert`` pastes
        PRIMARY in most terminals (kitty, ghostty, xterm/XWayland and GTK's own
        binding); ``wl-copy`` only ever fills the clipboard selection, so without this
        half of ``SUPER + V`` has nothing to paste. The PRIMARY write is best-effort:
        the clipboard is the contract, PRIMARY is what makes the terminals agree.
        """
        binary = tool("wl-copy")
        if binary is None:
            return None
        mime = UTI_MIME.get(uti or "") or "text/plain"
        if not self._offer(binary, data, mime, primary=False):
            return None
        if is_text_uti(uti):
            self._offer(binary, data, mime, primary=True)
        return mime

    def _offer(self, binary, data, mime, primary):
        """One `wl-copy` selection offer. False when the offer could not be made."""
        cmd = [binary, "--type", mime] + (["--primary"] if primary else [])
        try:
            subprocess.run(cmd, input=data, check=True, start_new_session=True,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10.0)
        except (OSError, subprocess.SubprocessError) as exc:
            if self.log is not None:
                # A failed PRIMARY offer is not a failed mirror: terminals that paste
                # the clipboard (foot, alacritty) still paste what we did serve.
                level = self.log.warn if primary else self.log.error
                level("wl-copy%s failed: %s" % (" --primary" if primary else "", exc))
            return False
        return True

    # -- "we wrote this" ---------------------------------------------------

    def remember(self, digest):
        if not digest:
            return
        self._written[digest] = True
        self._written.move_to_end(digest)
        while len(self._written) > WRITTEN_MAX:
            self._written.popitem(last=False)

    def known(self, digest):
        return bool(digest) and digest in self._written

    def written(self):
        return list(self._written)


def is_text_uti(uti):
    return uti in TEXT_UTIS
