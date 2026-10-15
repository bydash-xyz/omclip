#!/bin/sh
# Install omclip for the current user: the systemd user unit + the ~/.local/bin symlink.
# The logic lives in `omclip install` so there is exactly one implementation.
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$here/bin/omclip" install "$@"
