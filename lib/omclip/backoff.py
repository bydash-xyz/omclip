"""Reconnect backoff: 1/2/4/8/16/30 s with ±20 % jitter.

Jitter matters here: both peers are polled by the same process and a reconnect
storm on the shared 2.4 GHz antenna is exactly what the reference client's naive
retry loop produced.
"""

import random

SEQUENCE = (1.0, 2.0, 4.0, 8.0, 16.0, 30.0)
JITTER = 0.2
CAP = SEQUENCE[-1]


def base_delay(attempt):
    """Un-jittered delay for a 0-based consecutive-failure count (capped at 30 s)."""
    return SEQUENCE[min(max(int(attempt), 0), len(SEQUENCE) - 1)]


def delay(attempt, rand=None):
    """Jittered delay: base × (1 ± 20 %). `rand` returns [0, 1) (injectable for tests)."""
    rnd = random.random if rand is None else rand
    return base_delay(attempt) * (1.0 + (rnd() * 2.0 - 1.0) * JITTER)


def sequence(count):
    """The un-jittered sequence the daemon walks through (for docs and tests)."""
    return [base_delay(i) for i in range(count)]
