#!/bin/sh
# Remove the unit and the bin symlink. Settings and state are kept (see `omclip uninstall`).
set -eu
here=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
exec "$here/bin/omclip" uninstall "$@"
