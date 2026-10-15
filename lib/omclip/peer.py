"""Per-peer runtime model: the object `status.peers[]` describes.

Two peers exist, always in this order and always both present in the status
document: `mac` (the Mac's own `rapportd` on the LAN) and `phone` (the iPhone over
AWDL). A peer that is out of scope, or any peer while the daemon is off, reports
`state: "disabled"`.
"""

import time

from . import backoff

#: Stable keys and their fixed presentation. Labels may be upgraded to the name the
#: peer reports in its `_systemInfo` reply — the keys never change.
DEFAULT_LABELS = {"mac": "MacBook Pro", "phone": "iPhone"}
KIND = {"mac": "mac", "phone": "iphone"}
TRANSPORT = {"mac": "lan", "phone": "awdl"}
ORDER = ("mac", "phone")

#: Peer states and what they mean:
#:   disabled      not in scope (or the daemon is off)
#:   resolving     looking the peer up (mDNS / AWDL neighbour)
#:   connecting    TCP + Pair-Verify in flight
#:   authenticated session up, nothing polled yet
#:   polling       a payload request is in flight
#:   idle          session up, waiting for the next poll round
#:   locked        the iPhone answered nothing, which is what a locked phone does
#:   unreachable   no address to try (AWDL down, omdrop window closed)
#:   error         the last attempt failed (detail carries the reason)
STATES = ("disabled", "resolving", "connecting", "authenticated", "polling", "idle",
          "locked", "unreachable", "error")

HEALTHY_STATES = ("authenticated", "polling", "idle")


def blank_generation():
    return {"digest": None, "at": None, "uti": None, "bytes": None, "mirrored": False,
            "reason": None, "bulk": False}


class Peer:
    def __init__(self, key, *, in_scope=True, label=None, log=None):
        self.key = key
        self.kind = KIND[key]
        self.transport = TRANSPORT[key]
        self.in_scope = in_scope
        self.label = label or DEFAULT_LABELS[key]
        self.log = log

        self.address = None
        self.port = None
        self.state = "disabled" if not in_scope else "idle"
        self.detail = None
        self.last_seen = None
        self.last_error = None
        self.failures = 0                 # consecutive failures (schema: "attempts")
        self.last_generation = blank_generation()
        self.last_generation_at = None    # epoch of the last *new* generation

        self.session = None
        self.next_attempt = 0.0           # monotonic deadline for the next poll
        self.force_fast_until = 0.0       # set by a BLE 0x0c trigger
        self.last_bulk_digest = None      # log dedupe for repeated bulk generations
        self.mirrored_first = False
        self.attempted = False            # one poll round has been tried

    # -- presentation ------------------------------------------------------

    def to_status(self):
        return {
            "key": self.key,
            "kind": self.kind,
            "label": self.label,
            "transport": self.transport,
            "address": self.address,
            "port": self.port,
            "state": self.state,
            "detail": self.detail,
            "last_seen": self.last_seen,
            "last_error": self.last_error,
            "attempts": self.failures,
            "last_generation": dict(self.last_generation),
        }

    # -- state -------------------------------------------------------------

    def set_state(self, state, detail=None):
        assert state in STATES, state
        self.state = state
        self.detail = detail

    def on_success(self, now=None):
        """A completed exchange: the peer is healthy, backoff resets."""
        now = int(time.time() if now is None else now)
        self.last_seen = now
        self.failures = 0
        self.last_error = None
        # next_attempt is deliberately *not* reset here: the daemon arms it from the
        # adaptive cadence via _schedule() so a success cannot turn into a hot poll loop.
        if self.detail:
            self.detail = None

    def on_failure(self, message, *, now=None, detail=None, state="error"):
        """A failed attempt: record it, back off 1/2/4/8/16/30 s (±20 % jitter)."""
        now = int(time.time() if now is None else now)
        self.close_session()
        self.failures += 1
        self.last_error = message
        self.state = state
        self.detail = detail or message
        self.next_attempt = time.monotonic() + backoff.delay(self.failures - 1)
        return self.next_attempt

    def set_generation(self, decision, now=None):
        """Record what happened to one fetched generation (schema `last_generation`)."""
        now = int(time.time() if now is None else now)
        self.last_generation = {
            "digest": decision.digest,
            "at": now,
            "uti": decision.uti,
            "bytes": decision.data_size if decision.data_size is not None else (
                len(decision.data) if decision.data is not None else None),
            "mirrored": decision.mirror,
            "reason": decision.reason,
            "bulk": bool(decision.bulk),
        }
        self.last_generation_at = now
        if decision.mirror:
            self.mirrored_first = True

    def close_session(self):
        if self.session is not None:
            self.session.close()
            self.session = None


def peers_for_scope(scope, *, log=None):
    """Two peer objects, in scope order, from a scope list like ["mac", "phone"]."""
    return [Peer(key, in_scope=(key in scope), log=log) for key in ORDER]
