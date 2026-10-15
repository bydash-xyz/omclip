"""Filesystem layout: everything omclip owns, in one place."""

import os

UNIT_NAME = "omclip.service"
STATE_NAME = "status.json"

HOME = os.path.expanduser("~")

CONFIG_DIR = os.path.join(HOME, ".config", "omclip")
SETTINGS_FILE = os.path.join(CONFIG_DIR, "settings")

STATE_DIR = os.path.join(HOME, ".local", "state", "omclip")
STATUS_FILE = os.path.join(STATE_DIR, STATE_NAME)
DESIRED_FILE = os.path.join(STATE_DIR, "desired.json")
RUNTIME_FILE = os.path.join(STATE_DIR, "runtime.json")
PHONE_FILE = os.path.join(STATE_DIR, "phone.json")   # AWDL address that last resolved
BULK_DIR = os.path.join(STATE_DIR, "bulk")   # descriptor evidence for the bulk transfer
LOCK_FILE = os.path.join(STATE_DIR, "lock")
LOG_FILE = os.path.join(STATE_DIR, "omclip.log")

SYSTEMD_USER_DIR = os.path.join(HOME, ".config", "systemd", "user")
UNIT_FILE = os.path.join(SYSTEMD_USER_DIR, UNIT_NAME)
BIN_DIR = os.path.join(HOME, ".local", "bin")
BIN_LINK = os.path.join(BIN_DIR, "omclip")

#: The plugin symlink is owned by the plugin agent; omclip only ever creates it.
PLUGIN_DIR = os.path.join(HOME, ".config", "omarchy", "plugins")

#: Pair-Verify identity directory.
DEFAULT_IDENTITY_DIR = os.path.join(CONFIG_DIR, "identity")
DEFAULT_KEYS_DIR = os.path.join(HOME, ".omdrop", "keys")

#: Where the body of a copied file is written when the companion stream delivers it.
#: `~/Downloads` is where a user looks for a file that just arrived — the same directory
#: omdrop drops into — and `download_dir` moves it (`omclip config set download_dir …`,
#: an absolute path). A state directory was the alternative and was rejected: the file is
#: the user's, not ours, and a hidden path under `~/.local/state` is where files go to be
#: lost.
DEFAULT_DOWNLOAD_DIR = os.path.join(HOME, "Downloads")


def ensure_dir(path):
    """Create a directory with private modes (idempotent)."""
    os.makedirs(path, mode=0o700, exist_ok=True)
