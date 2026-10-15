"""One authenticated companion-link session with one peer — hardened.

Why this exists rather than reusing the reference client's `PeerSession`:

* **One session per peer** is a protocol *requirement*: rapportd accepts a second
  authenticated connection from the same identity and then closes the first
  (measured 2026-10-13). `omclip` therefore owns exactly one session object per
  peer and always closes before re-connecting.
* The reference `request()` retries `8 × 4 s` reads, so a lost reply costs 32 s and
  a reply that arrives after one of those windows is dropped. Here a single receive
  loop matches the `_x` echo under one absolute deadline (≤ 6 s), buffers
  unsolicited events instead of discarding them, and raises `PeerGone` immediately
  on EOF/reset so the caller can back off and re-authenticate.
* Every wait is sliced (≤ 250 ms) and checks a stop callback, so SIGTERM is honoured
  inside 250 ms even mid-request.
"""

import socket
import time
from collections import deque

from .protocol import (FRAME_OPACK, HANDOFF_ADV_PAYLOAD, PeerError, PeerGone,
                       RequestTimeout, StopRequested, ContentChannel,
                       announce_system_info, connect as tcp_connect, opack_decode,
                       opack_encode, pair_verify, recv_frame, send_frame, DEFAULT_MODEL)
from .pasteboard import parse_pasteboard_archive

#: A session with no successful exchange for this long is recycled before the next
#: poll: rapportd's own idle behaviour is not documented and a half-dead TCP
#: connection looks identical to an idle peer.
IDLE_RECYCLE_S = 30.0

WAIT_SLICE = 0.25


class Session:
    """Pair-Verify + announced `_systemInfo` + a correlated request loop."""

    def __init__(self, host, port, ed_sk, ed_pk_hex, ids_id, *, name=None,
                 model=DEFAULT_MODEL, iface=None, connect_timeout=5.0,
                 request_timeout=6.0, log=None):
        self.host, self.port = host, port
        self.iface = iface
        self.ed_sk, self.ed_pk_hex, self.ids_id = ed_sk, ed_pk_hex, ids_id
        self.name, self.model = name, model
        self.connect_timeout, self.request_timeout = connect_timeout, request_timeout
        self.log = log
        self.sock = None
        self.channel = None
        self.xid = 0
        self.last_exchange = None
        self.opened_at = None
        self.peer_name = None
        self.variant = None
        self.events = deque(maxlen=32)

    # -- lifecycle ---------------------------------------------------------

    def open(self):
        """Connect, run Pair-Verify, announce `_systemInfo`. Raises on failure."""
        self.close()                       # never overlap two sessions with one peer
        sock = tcp_connect(self.host, self.port, self.connect_timeout, self.iface)
        try:
            sock.settimeout(max(self.connect_timeout, 2.0))
            shared = pair_verify(sock, self.ed_sk, self.connect_timeout)
            self.sock = sock
            self.channel = ContentChannel(shared)
            self.opened_at = time.monotonic()
            self.last_exchange = self.opened_at
            self.xid = 0
            self.events.clear()
            self._debug("session: pair-verify ok (M1 appflags1)")
            self.announce()
        except Exception:
            self.close()
            raise
        return self

    def announce(self):
        """`_systemInfo` with our `_idsID`. Mandatory before every payload request."""
        self.xid = 1
        announce_system_info(self.sock, self.channel, self.ids_id, self.ed_pk_hex,
                             name=self.name, model=self.model, xid=1)

    def close(self):
        sock, self.sock = self.sock, None
        self.channel = None
        if sock is None:
            return
        try:
            sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            sock.close()
        except OSError:
            pass

    def __enter__(self):
        return self.open()

    def __exit__(self, *exc):
        self.close()

    # -- requests ----------------------------------------------------------

    def next_xid(self):
        self.xid = (self.xid or 0) + 1
        return self.xid

    def request(self, selector, content, deadline=None, should_stop=None):
        """Send one OPACK request, return the `_t == 3` response for its `_x`.

        Unsolicited frames (the `_systemInfo` reply, `_systemInfoUpdate`, handoff
        events) are buffered, never dropped and never mistaken for this reply.
        """
        if self.sock is None:
            raise PeerGone("no session")
        want = self.next_xid()
        body = opack_encode({"_i": selector, "_t": 2, "_x": want, "_c": content})
        try:
            send_frame(self.sock, FRAME_OPACK, body, self.channel)
        except OSError as exc:
            raise PeerGone("send failed: %s" % exc) from exc
        end = time.monotonic() + (deadline or self.request_timeout)
        while True:
            if should_stop is not None and should_stop():
                raise StopRequested()
            left = end - time.monotonic()
            if left <= 0:
                raise RequestTimeout("no response to %s (_x=%d)" % (selector, want))
            got = self._read(min(left, WAIT_SLICE))
            if got is None:
                continue
            ft, obj = got
            if isinstance(obj, dict) and obj.get("_t") == 3 and obj.get("_x") == want:
                if "_em" in obj:
                    raise PeerError("%s: _ec=%s %s" % (selector, obj.get("_ec"),
                                                       obj.get("_em")))
                self.last_exchange = time.monotonic()
                return obj
            self._note_event(ft, obj)

    def payload_request(self, command="pbpaste2", adv=HANDOFF_ADV_PAYLOAD, deadline=None,
                        should_stop=None):
        """`com.apple.handoff.payload-request`; returns (response, pasteboard or None)."""
        resp = self.request("com.apple.handoff.payload-request",
                            {"rAdvPayload": adv, "rClientCommand": command,
                             "rIdentifier": ""},
                            deadline=deadline, should_stop=should_stop)
        blob = (resp.get("_c") or {}).get("rActPayload")
        pb = None
        if blob:
            try:
                pb = parse_pasteboard_archive(blob)
            except Exception as exc:            # malformed archive: treat as no data
                self._debug("pasteboard archive decode failed: %s" % exc)
        return resp, pb

    def recycle_needed(self, now=None, limit=IDLE_RECYCLE_S):
        """True when the session has gone quiet for too long and should be replaced."""
        now = time.monotonic() if now is None else now
        return (self.last_exchange is None) or (now - self.last_exchange > limit)

    # -- internals ---------------------------------------------------------

    def _read(self, timeout):
        import select
        try:
            ready = select.select([self.sock], [], [], timeout)[0]
        except (OSError, ValueError) as exc:
            raise PeerGone("select failed: %s" % exc) from exc
        if not ready:
            return None
        ft, body = recv_frame(self.sock)          # PeerGone on EOF/reset
        if self.channel is None or not body:
            return ft, body
        aad = bytes([ft]) + len(body).to_bytes(3, "big")
        try:
            plain = self.channel.open(body, aad=aad)
        except ValueError as exc:
            # Counter desync: everything after this frame would be garbage.
            raise PeerGone("content channel desync: %s" % exc) from exc
        try:
            return ft, opack_decode(plain)[0]
        except ValueError:
            return ft, plain

    def _note_event(self, ft, obj):
        self.events.append({"at": time.time(), "frame": ft, "obj": obj})
        if isinstance(obj, dict):
            content = obj.get("_c")
            if isinstance(content, dict) and content.get("name"):
                self.peer_name = content["name"]
            selector = obj.get("_i")
            if selector in ("_systemInfoUpdate", "com.apple.handoff.payload-request"):
                self._debug("session: unsolicited %s (t=%s x=%s)"
                            % (selector, obj.get("_t"), obj.get("_x")))

    def _debug(self, msg):
        if self.log is not None:
            self.log.debug(msg)
