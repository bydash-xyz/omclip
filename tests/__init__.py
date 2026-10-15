"""Test package bootstrap.

`python3 -m unittest tests.test_foo` imports this package first; `discover -s tests`
does not, and relies on the start directory being on sys.path. This makes the tests
dir and `lib/` importable either way.
"""

import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
for path in (HERE, os.path.join(ROOT, "lib")):
    if path not in sys.path:
        sys.path.insert(0, path)
