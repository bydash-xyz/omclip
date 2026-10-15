"""The omclip daemon: one authenticated session per peer, adaptive polling, status.

Design notes (each one is a measured protocol fact or a constraint of this machine):

* **One session per peer.** rapportd closes the first authenticated connection when a
  second arrives, so the daemon owns exactly one `Session` per peer, always closes
  before re-connecting, and never probes a peer out of band.
* **Bounded, jittered backoff** on every failure (EOF/reset/timeout/refusal):
  1/2/4/8/16/30 s ±20 %, then re-authenticate and re-announce `_systemInfo`.
* **Adaptive cadence**: `poll_seconds` while a peer has been seen in the last 5 min
  (or for 60 s after a BLE `0x0c` trigger), `idle_poll_seconds` once nothing has moved,
  `locked_poll_seconds` when the iPhone is locked. No busy loop: the loop sleeps in
  `select` and writes status at ~1 Hz.
* **Cheap by construction**: stdlib only, no thread per peer, no polling of anything
  that is not due. Target: RSS well under 40 MB, ≤ 1 % CPU at idle.
* **Honest states**: no reachable peer while the unit is on is `degraded` with the
  reasons in `errors`, never a cheerful `on`.
"""

import fcntl
import os
import re
import select
import signal
import socket
import subprocess
import threading
import time
from . import VERSION
from . import ble
from . import bluetooth
from . import bulk as bulkmod
from . import clipboard as clipmod
from . import credentials
from . import crypto
from . import discovery
from . import duration as durationmod
from . import identity as identitymod
from . import log as logmod
from . import omdrop
from . import paths
from . import pasteboard
from . import peer as peermod
from . import protocol
from . import session as sessionmod
from . import state
from . import status as statusmod

POLL_FAST_WINDOW_S = 60.0      # fast cadence window after a BLE 0x0c trigger
RECENT_ACTIVITY_S = 300.0      # a peer seen this recently keeps the fast cadence
BLE_RATE_LIMIT_S = 2.0         # never more than one trigger-driven round per 2 s
STATUS_WRITE_S = 0.9           # ≥ 1 Hz
HEALTH_REFRESH_S = 30.0        # display-only: `status` re-probes live on every call
CREDENTIAL_REFRESH_S = 300.0   # certs expire in weeks; one openssl spawn per 5 min
TICK_S = 1.0
PHONE_MAX_NEIGHBOURS = 8       # asked at once from one socket; live peers first
OMDROP_RETRY_S = 60.0      # a failed `omdrop on` is retried, not forgotten
#: A bulk generation whose fetch failed is retried this often, not on every poll: the
#: descriptor repeats for as long as the sender holds the copy (measured: 732 `bulk`
#: skips for one generation at the 2 s cadence), and a transient failure — the Mac
#: asleep, avahi busy — must still recover without the user copying anything again.
BULK_RETRY_S = 30.0
MDNS_CACHE_S = 300.0       # a rapportd port rarely changes; a lookup costs ~1 s of CPU
AVAHI_CACHE_S = 300.0     # the avahi fallback is a 1 s subprocess: at most once per 5 min
OMPDROP_STOP_TIMEOUT = 4.0     # `omdrop off`'s supervisor also releases the radio


def landed_field(files):
    """`<absolute path> (<n> B)` for each landed file → one log field, or None.

    The path is ours (under `download_dir`), so it is safe to log and it is the only way
    a user can tell where a fetched file went. The *sender's* path and the payload's bytes
    are deliberately absent, and a path is never a file's content.
    """
    return ", ".join("%s (%d B)" % (f.path, f.bytes) for f in files) or None


def file_doc(landed):
    """`clipboard.last_file` for one landed file: its name, path and size — never content."""
    if landed is None:
        return None
    return {"name": landed.name, "path": landed.path, "bytes": landed.bytes}


class Resolution:
    """Outcome of looking a peer up: an address to dial, or why we cannot.

    `state` is None when the lookup succeeded. `seen_address`/`seen_port` are the honest
    *display* pair for a lookup that could not resolve, so the status document can still
    show the user something concrete: `seen_address` is only ever an address this daemon has
    actually resolved for that peer before — never a candidate that merely got asked, and so
    never an address `_is_the_mac()` rejected — and `seen_port` is the port that came with
    it (None when unknown), never another peer's port. An address and a port from two
    different peers must never be published side by side.
    """

    __slots__ = ("address", "port", "state", "detail", "seen_address", "seen_port")

    def __init__(self, address=None, port=None, state=None, detail=None, seen_address=None,
                 seen_port=None):
        self.address = address
        self.port = port
        self.state = state
        self.detail = detail
        self.seen_address = seen_address or address
        self.seen_port = seen_port if seen_address else port

    def __repr__(self):
        return "Resolution(%s:%s, state=%s, detail=%s)" % (self.address, self.port,
                                                           self.state, self.detail)


class Daemon:
    def __init__(self, settings, log=None):
        self.settings = settings
        self.log = log or logmod.Logger(None)
        self.started_at = time.time()
        self.scope = list(settings.scopes())
        self.window = None
        self.identity = None
        self.fatal = []
        self.stop_event = None            # set in run()
        self.stop_reason = None
        self.peers = peermod.peers_for_scope(self.scope, log=self.log)
        self.by_key = {p.key: p for p in self.peers}
        self.clip = clipmod.Clipboard(log=self.log)
        #: `bulk.fetch`, replaceable so tests never open a socket.
        self.bulk_fetch = bulkmod.fetch
        #: peer key → the last bulk generation attempted for it (see `_bulk_generation`)
        self._bulk_seen = {}
        self.omdrop_status = None
        self.omdrop_owned = False
        self.bluetooth_owned = False
        self.bluetooth_ready = False
        self.bluetooth_pre_existing = False
        self.bluetooth_error = None
        self.omdrop_window = None
        self.omdrop_error = None      # why the last `omdrop on` attempt failed
        self.omdrop_retry_at = 0.0
        self.ble_backend = "unknown"
        self.ble_detail = None
        self.monitor = None
        self.first_round_done = False
        self.last_write = 0.0
        self.last_health = 0.0
        self.last_ble_trigger = 0.0
        self._mac_mdns = None          # last resolved instance (or None if none found)
        self._mac_mdns_at = 0.0        # when the lookup last ran — success or not
        self._mac_avahi_at = 0.0       # when avahi-browse was last spawned
        self._mac_host_name = None     # SRV target of the matched instance (host memory)
        self._phone_last_good = None   # AWDL address that last resolved (tried first)
        self._mac_awdl = set()         # AWDL addresses that turned out to be the Mac
        self._lock_fd = None
        self._wake_r = self._wake_w = None
        self._health = None
        self._creds = None
        self.last_creds = 0.0
        self._logged_skip = {}
        self.last_oversize_error = None
        self._logged_oversize = {}
        # clipboard rollup (schema `clipboard`)
        self.mirrored_total = 0
        self.last_mirrored_at = None
        self.last_digest = None
        self.last_uti = None
        self.last_bytes = None
        self.last_file = None
        self.last_preview = None
        self.counters = {reason: 0 for reason in statusmod.SKIP_REASONS}

    # ------------------------------------------------------------------ run

    def run(self):
        """Entry point for `omclip daemon`. Returns a process exit code."""
        if not self._acquire_lock():
            self.log.info("another omclip daemon holds the lock; exiting 0")
            print("omclip: already running", flush=True)
            return 0
        self.stop_event = _new_stop_event()
        _install_signal_handlers(self.stop_event)
        clipmod.adopt_wayland_env()
        self.identity, error = identitymod.load(self.settings["identity_dir"])
        if error:
            self.fatal.append(error)
            self.log.error("identity unavailable: %s" % error)
        desired = state.load_desired()
        self._open_window(desired)
        self._phone_last_good = state.load_phone().get("last_good")
        self._wake_r, self._wake_w = socket.socketpair()
        self._wake_r.setblocking(False)
        self.log.info("daemon started", pid=os.getpid(), scope=",".join(self.scope),
                      duration=self.window.duration, ids=",".join(
                          p.key for p in self.peers if p.in_scope))
        self._check_credentials(force=True)
        # Immediately publish initial "starting" status before slow hardware/network ops
        state.save_runtime({
            "pid": os.getpid(), "started_at": int(self.started_at),
            "since": int(self.window.since), "expires_at": self.window.expires_at,
            "duration": self.window.duration, "scope": self.scope,
            "bluetooth_owned": self.bluetooth_owned,
            "omdrop_owned": self.omdrop_owned, "omdrop_window": self.omdrop_window,
        })
        self._write_status(force=True)
        # Learn the Mac's mDNS identity *before* the loop, so an AWDL neighbour query can
        # always be filtered against it. Without this the ordering could hand the Mac to the
        # phone peer (measured: it reported as "User's Mac" on port 49152 under the
        # "phone" key when the LAN lookup had not completed yet).
        if "phone" in self.scope:
            self._prime_mac_identity()
            # The radio comes up before the BLE monitor registers and before omdrop's
            # window: an iPhone asleep on AWDL is only reachable while a wake
            # advertisement goes out, and that needs bluetoothd and a powered adapter.
            self._ensure_bluetooth()
        self._start_ble()
        self._open_omdrop_window()
        state.save_runtime({
            "pid": os.getpid(), "started_at": int(self.started_at),
            "since": int(self.window.since), "expires_at": self.window.expires_at,
            "duration": self.window.duration, "scope": self.scope,
            "bluetooth_owned": self.bluetooth_owned,
            "omdrop_owned": self.omdrop_owned, "omdrop_window": self.omdrop_window,
        })
        self._write_status(force=True)
        try:
            self._loop()
        finally:
            self._shutdown()
        return 0

    # --------------------------------------------------------------- window

    def _open_window(self, desired):
        canonical, seconds, once = durationmod.parse_duration(
            (desired or {}).get("duration") or self.settings["duration"])
        self.window = durationmod.Window(canonical, seconds, once)
        if (desired or {}).get("scope"):
            self.scope = [k for k in peermod.ORDER if k in desired["scope"]]
            self.peers = peermod.peers_for_scope(self.scope, log=self.log)
            self.by_key = {p.key: p for p in self.peers}

    # --------------------------------------------------------------- main loop

    def _loop(self):
        while not self.stop_event.is_set():
            now_m = time.monotonic()
            for peer in self.peers:
                if not peer.in_scope or self.stop_event.is_set():
                    continue
                if now_m >= peer.next_attempt:
                    self._poll_peer(peer)
            self.first_round_done = all(p.attempted for p in self.peers if p.in_scope)
            self._tick_omdrop()
            if self.window.expired():
                self.stop_reason = "expired"
                self.log.info("window expired", duration=self.window.duration)
                break
            if self.stop_reason:
                break
            self._write_status()
            self._wait(now_m)

    def _wait(self, now_m):
        """Sleep until the next due poll / status write / trigger, honouring stop."""
        due = [p.next_attempt for p in self.peers if p.in_scope and p.next_attempt > now_m]
        timeout = TICK_S
        if due:
            timeout = min(timeout, max(0.05, min(due) - now_m))
        timeout = min(timeout, max(0.05, STATUS_WRITE_S - (time.monotonic() - self.last_write)))
        try:
            ready = select.select([self._wake_r], [], [], timeout)[0]
        except (OSError, ValueError):
            return
        if ready:
            try:
                self._wake_r.recv(4096)
            except OSError:
                pass

    # --------------------------------------------------------------- polling

    def _poll_peer(self, peer):
        if self.stop_event.is_set():
            return
        peer.attempted = True
        if peer.session is not None and peer.session.recycle_needed():
            self.log.debug("recycling idle session", peer=peer.key)
            peer.close_session()
            if peer.state in peermod.HEALTHY_STATES:
                peer.set_state("idle")
        if peer.session is None and not self._ensure_session(peer):
            return
        peer.set_state("polling")
        try:
            _resp, pb = peer.session.payload_request(
                should_stop=self.stop_event.is_set)
        except protocol.StopRequested:
            return
        except protocol.PeerGone as exc:
            self._fail(peer, "peer gone: %s" % exc)
            return
        except protocol.RequestTimeout as exc:
            self._fail(peer, str(exc))
            return
        except protocol.PeerError as exc:
            self._fail(peer, "refused: %s" % exc)
            return
        except OSError as exc:
            self._fail(peer, "socket error: %s" % exc)
            return
        except Exception as exc:                    # noqa: BLE001 - keep the loop alive
            self._fail(peer, "unexpected: %r" % exc)
            return
        peer.on_success()
        peer.set_state("idle")
        if peer.key == "phone" and self._phone_peer_is_the_mac(peer):
            self.log.warn("phone peer connected to the Mac (%s); dropping it"
                          % (peer.session.peer_name or "unnamed"))
            peer.close_session()
            peer.set_state("unreachable", "the AWDL peer is the Mac, not an iPhone")
            peer.label = peermod.DEFAULT_LABELS["phone"]
            self._schedule(peer)
            return
        peer.label = peer.session.peer_name or peer.label
        self._handle_pasteboard(peer, pb)
        # Arm the *next* poll from the adaptive cadence. Without this a successful poll
        # leaves the deadline at 0 and the loop hammers the peer once per tick (~1 Hz
        # measured) — it also kept the Mac's rapportd answering a request a second.
        self._schedule(peer)

    def _fail(self, peer, message):
        """Record a failure with backoff and one log line per state change."""
        attempt = peer.failures + 1
        peer.on_failure(message, detail=message)
        # One line per streak (and every 5th): a 30 s backoff would otherwise fill the
        # 512 KB log with the same line for hours.
        if attempt == 1 or attempt % 5 == 0:
            self.log.warn("peer attempt failed", peer=peer.key, error=message,
                          attempt=attempt, next_in_s=round(peer.next_attempt - time.monotonic(), 1))
        else:
            self.log.debug("peer attempt failed", peer=peer.key, error=message,
                           attempt=attempt)
        self._schedule(peer)

    def _schedule(self, peer):
        """Arm the next poll from the adaptive cadence (or keep a pending backoff deadline)."""
        now = time.monotonic()
        if peer.next_attempt > now:
            return                                   # a backoff or trigger already set one
        peer.next_attempt = now + self.cadence(peer)

    def cadence(self, peer):
        if peer.state == "locked":
            return float(self.settings["locked_poll_seconds"])
        now = time.monotonic()
        if peer.force_fast_until > now:
            return float(self.settings["poll_seconds"])
        if peer.last_seen and time.time() - peer.last_seen < RECENT_ACTIVITY_S:
            return float(self.settings["poll_seconds"])
        return float(self.settings["idle_poll_seconds"])

    # --------------------------------------------------------------- sessions

    def _ensure_session(self, peer):
        if self.identity is None:
            return False
        peer.set_state("resolving")
        try:
            found = self._resolve(peer)
        except Exception as exc:                    # noqa: BLE001 - discovery must not kill us
            self._fail(peer, "discovery failed: %r" % exc)
            self._schedule(peer)
            return False
        if found.state is not None:
            if found.seen_address:
                # Published as a pair: a lookup that could not dial must not leave one
                # device's port next to another device's address (measured 2026-10-14:
                # status.json showed the phone peer as the Mac's AWDL link-local with the
                # iPhone's ephemeral port).
                peer.address, peer.port = found.seen_address, found.seen_port
            peer.state = found.state
            peer.detail = found.detail
            if found.state == "unreachable":
                peer.next_attempt = time.monotonic() + float(
                    self.settings["idle_poll_seconds"])
            elif found.state == "locked":
                peer.next_attempt = time.monotonic() + float(
                    self.settings["locked_poll_seconds"])
            else:
                peer.on_failure(found.detail or found.state, detail=found.detail,
                                state=found.state)
            return False
        address, port = found.address, int(found.port)
        peer.address, peer.port = address, port
        peer.set_state("connecting")
        try:
            session = sessionmod.Session(
                address, port, self.identity.ed_sk, self.identity.ed_pk_hex,
                self.identity.ids_id, name=None,
                iface="awdl0" if peer.key == "phone" else None, log=self.log)
            session.open()
        except protocol.AuthFailed as exc:
            self._fail(peer, "pair-verify failed: %s" % exc)
            return False
        except (protocol.PeerError, OSError) as exc:
            self._fail(peer, "%s" % exc)
            return False
        except Exception as exc:                    # noqa: BLE001
            self._fail(peer, "connect failed: %r" % exc)
            return False
        peer.session = session
        peer.set_state("authenticated")
        self.log.info("peer session up", peer=peer.key, address=address, port=port)
        return True

    def _resolve(self, peer):
        """Look one peer up. Returns a `Resolution`."""
        if peer.key == "phone":
            return self._resolve_phone(peer)
        return self._resolve_mac(peer)

    def _resolve_mac(self, peer):
        """The Mac's own `rapportd`, found by mDNS for the port, addressed by `mac_host`.

        The address is deliberately not taken from mDNS: several devices answer
        `_companion-link` on a home LAN (an Apple TV does here), so an instance is only
        trusted when it reports the address we are already configured to talk to.
        """
        host = self.settings["mac_host"]
        port = int(self.settings["mac_port"])
        now = time.monotonic()
        # Negative results are cached too: a failed lookup costs an mDNS round plus an
        # `avahi-browse` subprocess, and re-running that every 2 s poll (which an earlier
        # version did) is both a wakeup and a CPU problem.
        if now - self._mac_mdns_at > MDNS_CACHE_S:
            instance = self._lookup_mac_instance(host)
            if instance is None and now - self._mac_avahi_at > AVAHI_CACHE_S:
                # avahi-browse is a LAN convenience only (it cannot see awdl0) and costs
                # ~1 s of CPU per spawn, so it is consulted at most every 5 minutes.
                self._mac_avahi_at = now
                try:
                    instance = discovery.pick_instance(discovery.avahi_browse(), host)
                except OSError as exc:
                    self.log.debug("avahi-browse failed: %s" % exc)
            self._mac_mdns = instance
            self._mac_mdns_at = now
            if instance:
                self.log.debug("mac resolved via mDNS", name=instance.name,
                               port=instance.port, address=instance.address)
        if self._mac_mdns is not None:
            if self._mac_mdns.port:
                port = int(self._mac_mdns.port)
            if self._mac_mdns.name:
                peer.label = self._mac_mdns.name
        return Resolution(host, port)

    def _prime_mac_identity(self):
        """Run the Mac's mDNS lookup once at startup and cache the result."""
        instance = self._lookup_mac_instance(self.settings["mac_host"])
        self._mac_mdns = instance
        self._mac_mdns_at = time.monotonic()
        if instance:
            self.log.debug("mac identity primed", host=instance.host, port=instance.port)
        else:
            self.log.debug("mac identity unknown; AWDL results cannot be filtered against it "
                           "(set phone_address to pin the iPhone)")

    def _lookup_mac_instance(self, host):
        """The Mac's `_companion-link` instance, or None.

        Two passes, because the A record for the SRV target arrives in a later packet and
        a single pass can miss it. Once an instance has matched by address we remember its
        SRV target host name and accept a match on that name alone — `rapportd`'s own port
        is what we want, and the address is already known from `mac_host`.
        """
        iface = discovery.lan_interface(host)
        if not iface:
            return None
        for _attempt in range(2):
            try:
                instances = discovery.resolve_companion_link(iface, timeout=1.5)
            except OSError as exc:
                self.log.debug("mDNS on %s failed: %s" % (iface, exc))
                return None
            instance = (discovery.pick_instance(instances, host)
                        or discovery.pick_by_host(instances, self._mac_host_name))
            if not instance:
                mac_port = int(self.settings.get("mac_port") or 49152)
                for inst in instances:
                    if inst.port and (inst.port == mac_port or "mac" in (inst.name or "").lower()):
                        instance = inst
                        break
            if instance:
                self._mac_host_name = instance.host
                return instance
        return None

    def _is_the_mac(self, instance):
        """True when an AWDL discovery result is the Mac we already mirror over the LAN.

        Host name, advertised instance name and the well-known `mac_port` are all used: the
        Mac answers `_companion-link` over AWDL too, on its own rapportd port, and mirroring it
        under the `phone` key as well would poll one device twice.
        """
        if not instance:
            return False
        # macOS rapportd runs on fixed well-known port 49152; iOS uses ephemeral ports.
        mac_port = int(self.settings.get("mac_port") or 49152)
        if instance.port and instance.port == mac_port:
            return True
        name_lower = (instance.name or "").lower()
        if "mac" in name_lower or "macbook" in name_lower:
            return True
        if self._mac_host_name and instance.host == self._mac_host_name:
            return True
        if self._mac_mdns is not None:
            if instance.host == self._mac_mdns.host:
                return True
            if instance.name and instance.name == self._mac_mdns.name:
                return True
            if instance.address and (instance.address == self._mac_mdns.address or
                                     instance.address in getattr(self._mac_mdns, "addresses", [])):
                return True
            if any(a in getattr(self._mac_mdns, "addresses", []) for a in getattr(instance, "addresses", [])):
                return True
        mac_peer = self.by_key.get("mac")
        if mac_peer and mac_peer.label:
            mac_label_lower = mac_peer.label.lower()
            if mac_label_lower == name_lower or (len(name_lower) >= 4 and name_lower in mac_label_lower):
                return True
        mac_host = self.settings.get("mac_host")
        if mac_host and (instance.address == mac_host or mac_host in getattr(instance, "addresses", [])):
            return True
        return False

    def _phone_peer_is_the_mac(self, peer):
        """True when a session opened for the `phone` key actually reached the Mac.

        The Mac advertises `_companion-link` over AWDL too (measured: it answers as
        `CLink-…` on its fixed rapportd port), so a phone session that reports the
        Mac's own name is the *same device* already mirrored as `mac`. Mirroring it
        under both keys would poll one machine twice and show it twice in the UI, so
        such a session is dropped and the phone peer left honestly unreachable.
        """
        if peer.session is None:
            return False
        name = (peer.session.peer_name or "").strip().lower()
        if not name:
            return False
        if "mac" in name or "macbook" in name:
            return True
        mac_peer = self.by_key.get("mac")
        mac_label = (mac_peer.label if mac_peer else "").strip().lower()
        return bool(mac_label) and (mac_label == name
                                    or (len(name) >= 4 and name in mac_label))

    def _resolve_phone(self, peer):
        """AWDL: live peers, then unicast mDNS queries to all of them for the ephemeral port.

        Candidates come from omdrop's live AWDL peer table, strongest signal first. The
        neighbour table is only the fallback: it accumulates PERMANENT entries for every
        device ever heard (measured 2026-10-13: 31 rows, the iPhone 14th, behind a cap of 4,
        so it was never asked). The address that last resolved is tried first and survives
        restarts (`phone.json`); AWDL addresses that turned out to be the Mac are skipped.
        All candidates are asked at once and silent ones asked again — the iPhone ignored a
        first query and answered the repeat. Re-resolved on every attempt, because iOS mints
        a fresh port per service start.
        """
        self._refresh_omdrop()
        if discovery.awdl_up() is False:
            if self.omdrop_error:
                return Resolution(state="unreachable", detail=(
                    "could not open an omdrop window: %s" % self.omdrop_error))
            return Resolution(state="unreachable", detail=(
                "awdl0 is down: the iPhone needs an omdrop window "
                "(`omdrop on <duration>`; omclip only opens one when it owns it)"))
        if self.settings["phone_address"]:
            candidates = [self.settings["phone_address"]]
        else:
            live = discovery.awdl_live_peers()
            if live is None:
                candidates = list(discovery.awdl_neighbors())
                if self._phone_last_good in candidates:
                    candidates.remove(self._phone_last_good)
                    candidates.insert(0, self._phone_last_good)
            else:
                # Only peers in range now: a remembered address that is not live belonged
                # to a MAC the iPhone has since rotated away from.
                candidates = list(live)
                if self._phone_last_good in candidates:
                    candidates.remove(self._phone_last_good)
                    candidates.insert(0, self._phone_last_good)
            candidates = [a for a in candidates if a not in self._mac_awdl] or candidates
            candidates = candidates[:PHONE_MAX_NEIGHBOURS]
        if not candidates:
            return Resolution(state="unreachable", detail=(
                "no AWDL neighbour on awdl0 (iPhone out of range, or the omdrop "
                "window has closed)"))
        answers = discovery.resolve_companion_link_many(
            "awdl0", candidates, accept=lambda _address, inst: not self._is_the_mac(inst))
        mac_seen = False
        for address in candidates:
            instance = discovery.first_instance(answers.get(address) or [],
                                                (discovery.COMPANION,))
            if instance is None or not instance.port:
                continue
            if self._is_the_mac(instance):
                # Measured 2026-10-13: the Mac advertises `_companion-link` over AWDL too, so
                # it answers an AWDL neighbour query and would otherwise be mirrored twice —
                # once as "mac" and once as "phone" (it reported as "User's Mac" on
                # port 49152, its well-known rapportd port).
                mac_seen = True
                self._mac_awdl.add(address)
                self.log.debug("awdl neighbour is the Mac, not the iPhone",
                               host=instance.host, address=address)
                continue
            self._remember_phone(address)
            if instance.name:
                peer.label = instance.name
            return Resolution(address, int(instance.port))
        if self._phone_last_good in candidates and self._phone_last_good not in answers:
            # The iPhone we know is in AWDL range right now and silent — measured
            # 2026-10-13: it answers `empty` polls, then stops answering both rapportd and
            # mDNS the moment it locks, while the Mac keeps answering. That is `locked`, not
            # "the only peer is the Mac". The remembered address is the only one worth
            # showing: this daemon resolved it for the iPhone before, and its port travels
            # with it only when it is the port that came from that same address.
            return Resolution(state="locked", detail=(
                "iPhone must be unlocked: it is in AWDL range (%s) but not answering"
                % self._phone_last_good), seen_address=self._phone_last_good,
                seen_port=peer.port if peer.address == self._phone_last_good else None)
        if mac_seen:
            # No address here on purpose: the only `_companion-link` peer in range is the
            # Mac, so there is no iPhone address to show. A candidate we merely asked is
            # not the iPhone — measured 2026-10-14, publishing `candidates[0]` put the
            # Mac's AWDL link-local (fe80::e020:b4ff:fef6:65b5) in the phone peer's
            # `address` next to the iPhone's port, while this very detail said the only
            # peer was the Mac.
            return Resolution(state="unreachable", detail=(
                "the only _companion-link peer on awdl0 is the Mac; the iPhone is not "
                "advertising (unlocked and in range?) — pin it with `omclip config set "
                "phone_address <link-local>` if it is"))
        # Nothing answered, which is what a locked iPhone does (it stops answering its
        # rapportd entirely) — but "off / out of range" is indistinguishable from here, so
        # the detail carries the evidence rather than a verdict. Again no address: the
        # neighbours that stayed silent were only asked, never identified.
        return Resolution(state="locked", detail=(
            "iPhone must be unlocked: no _companion-link answer from %s AWDL neighbour%s"
            % (len(candidates), "" if len(candidates) == 1 else "s")))

    def _remember_phone(self, address):
        if address == self._phone_last_good:
            return
        self._phone_last_good = address
        try:
            state.save_phone({"last_good": address, "at": int(time.time())})
        except OSError as exc:
            self.log.debug("could not save phone.json", error=str(exc))

    # --------------------------------------------------------------- mirroring

    def _handle_pasteboard(self, peer, pb):
        file_uri = None
        landed = []
        if pb is not None and pb.get("bulk"):
            pb, file_uri, landed, finished = self._bulk_generation(peer, pb)
            if finished is not None:
                # The generation is done with: either the payload arrived and its
                # representation was already decided, or this attempt did not get it.
                peer.set_generation(finished)
                self._log_decision(peer, finished, pb)
                if finished.reason == "oversize":
                    self._handle_oversize(peer, finished)
                self.counters[finished.reason] = self.counters.get(finished.reason, 0) + 1
                return
        local = None
        if pb is not None and not pb.get("bulk"):
            uti, _data = pasteboard.best_representation(pb)
            if uti:
                local = self.clip.read_local(pasteboard.UTI_MIME.get(uti))
        decision = pasteboard.decide(
            pb,
            prev_digest=peer.last_generation.get("digest"),
            written=self.clip.written(),
            local=local,
            max_bytes=int(self.settings["max_bytes"]),
            file_uri=file_uri)
        if pb is not None and pb.get("fetched"):
            # `decide()` must see a plain pasteboard (it slices `extra_data`), but the
            # *generation* was deferred, so `status` keeps saying so next to `reason`.
            decision.bulk = True
        peer.set_generation(decision)
        self._log_decision(peer, decision, pb)
        if decision.reason == "oversize":
            self._handle_oversize(peer, decision)
        if decision.reason == "mirror":
            self.last_oversize_error = None
            peer.last_error = None
            self._logged_oversize.pop(peer.key, None)
            mime = self.clip.copy(decision.data, decision.uti)
            if mime is None:
                # Never claim a mirror that did not happen: the peer's generation is
                # recorded, then corrected.
                peer.last_generation["mirrored"] = False
                peer.last_error = "clipboard write failed"
                self.log.error("clipboard write failed; item not mirrored",
                               peer=peer.key, uti=decision.uti)
                return
            self.clip.remember(decision.digest)
            self.mirrored_total += 1
            self.last_mirrored_at = int(time.time())
            self.last_digest = decision.digest
            self.last_uti = decision.uti
            # A file mirror offers the `file://` URI (48 bytes here); reporting *that* size
            # would describe the URI, not the file the user copied. Every size this daemon
            # reports for such a mirror is the landed file's, and `last_file` carries its
            # name and path so no display has to guess from the bytes.
            landed_file = landed[0] if landed else None
            self.last_file = file_doc(landed_file)
            self.last_bytes = landed_file.bytes if landed_file else len(decision.data)
            if landed_file is not None:
                peer.last_generation["bytes"] = landed_file.bytes
            if self.settings["preview"]:
                self.last_preview = pasteboard.preview_of(decision.uti, decision.data)
            self.log.info("mirrored", peer=peer.key, uti=decision.uti,
                          bytes=self.last_bytes, landed=landed_field(landed),
                          digest=decision.digest[:12])
            self._notify(peer, decision, landed_file)
            if self.window.once:
                self.stop_reason = "once"
        else:
            self.counters[decision.reason] = self.counters.get(decision.reason, 0) + 1

    def _handle_oversize(self, peer, decision):
        peer.last_error = decision.detail
        self.last_oversize_error = "%s: %s" % (peer.key, decision.detail)
        self._write_status(force=True)
        key = (decision.digest or "oversize:%s" % decision.data_size, decision.detail)
        if self._logged_oversize.get(peer.key) != key:
            self._logged_oversize[peer.key] = key
            self.log.error("clipboard item exceeds max_bytes", peer=peer.key,
                           bytes=decision.data_size,
                           max_bytes=int(self.settings["max_bytes"]),
                           detail=decision.detail)
            self._notify(peer, decision)

    def _bulk_generation(self, peer, pb):
        """Fetch the bytes a bulk generation defers to, at most once per generation.

        Returns `(pasteboard, file_uri, landed, None)` when the payload arrived: a pasteboard
        shaped like an inlined one, so every existing representation, digest, echo and
        `max_bytes` rule applies to the fetched bytes, `file_uri` the URI of the first landed
        file (what `decide` offers) and `landed` every `LandedFile` written under
        `download_dir` (empty when the generation deferred no file body, or refused it).
        Returns `(None, None, [], Decision)` when this generation is finished with —
        `unchanged` for one already attempted (the descriptor repeats on every poll for as
        long as the sender holds the copy) and `bulk`/`oversize` when the attempt itself did
        not deliver.

        A failed attempt never counts as a peer failure: the session was healthy, only the
        separate `_continuity._tcp` connection to the holder failed, so the peer's backoff
        is untouched.
        """
        key = bulkmod.generation_key(pb)
        seen = self._bulk_seen.get(peer.key)
        now = time.monotonic()
        if seen and seen["key"] == key and (seen["done"] or now - seen["at"] < BULK_RETRY_S):
            return None, None, [], pasteboard.Decision(
                "unchanged", bulk=True, data_size=pb.get("data_size"),
                detail="bulk generation already attempted")
        first = not seen or seen["key"] != key
        evidence = self._save_bulk_evidence(peer, pb) if first else None
        self._bulk_seen[peer.key] = {"key": key, "at": now, "done": False,
                                     "evidence": evidence}
        self.log.debug("fetching the deferred bulk payload", peer=peer.key,
                       data_size=pb.get("data_size"), evidence=evidence)
        awdl = peermod.TRANSPORT.get(peer.key) == "awdl"
        try:
            payload = self.bulk_fetch(
                pb, keys_dir=self.settings["keys_dir"],
                max_bytes=int(self.settings["max_bytes"]),
                download_dir=self.settings.get("download_dir"),
                address=peer.address if awdl else None,
                iface="awdl0" if awdl else None,
                log=lambda text: self.log.debug("bulk: %s" % text, peer=peer.key))
        except bulkmod.Refused as exc:
            # Our own limit or a layout we do not decode: retrying changes nothing.
            self._bulk_seen[peer.key]["done"] = True
            return None, None, [], pasteboard.Decision(
                "oversize" if "max_bytes" in str(exc) else "bulk", bulk=True,
                data_size=pb.get("data_size"), detail=str(exc))
        except bulkmod.BulkError as exc:
            self.log.debug("bulk fetch failed", peer=peer.key, detail=str(exc))
            return None, None, [], pasteboard.Decision("bulk", bulk=True,
                                                       data_size=pb.get("data_size"),
                                                       detail=str(exc))
        except Exception as exc:                     # noqa: BLE001 - never kill the poll
            self.log.warn("bulk fetch raised %s" % type(exc).__name__, peer=peer.key,
                          detail=str(exc))
            return None, None, [], pasteboard.Decision(
                "bulk", bulk=True, data_size=pb.get("data_size"),
                detail="%s: %s" % (type(exc).__name__, exc))
        self._bulk_seen[peer.key]["done"] = True
        oversize_refused = next((r for r in payload.refused if r.get("oversize")), None)
        if oversize_refused is not None or (pasteboard.has_file_item(pb) and not payload.files and payload.refused):
            refused_item = oversize_refused or payload.refused[0]
            err = refused_item["error"]
            is_oversize = bool(refused_item.get("oversize") or "> max_bytes" in err)
            reason = "oversize" if is_oversize else "bulk"
            if is_oversize:
                self.log.error("bulk file exceeds max_bytes; not mirrored",
                               peer=peer.key, error=err)
            else:
                self.log.error("bulk file not landed; not mirrored",
                               peer=peer.key, error=err)
            m = re.search(r'(\d+)\s+bytes\s*>', err)
            refused_size = int(m.group(1)) if m else pb.get("data_size")
            decision = pasteboard.Decision(
                reason, bulk=True, uti="public.file-url",
                data_size=refused_size, detail=err)
            return None, None, [], decision

        for refused in payload.refused:
            self.log.info("bulk file not landed", peer=peer.key, error=refused["error"])
        self.log.info("bulk payload fetched", peer=peer.key, bytes=payload.data_size,
                      files=len(payload.files), landed=landed_field(payload.files),
                      endpoint="%s:%s" % (payload.endpoint or ("", "")))
        return (payload.as_inline(), payload.files[0].uri if payload.files else None,
                payload.files, None)

    def _log_decision(self, peer, decision, pb=None):
        """One log line per distinct (generation, reason) — silent polling otherwise."""
        key = (decision.digest or "bulk:%s" % (decision.data_size,), decision.reason)
        if self._logged_skip.get(peer.key) == key:
            return
        self._logged_skip[peer.key] = key
        if decision.reason == "bulk":
            # The payload is fetched in `_bulk_generation`; this line reports what came of
            # it, at most once per generation (the descriptor repeats every poll).
            detail = decision.detail
            if not pb and not detail:
                detail = "bulk payload not fetched"
            self.log.info("peer pasteboard is bulk mode; not mirrored",
                          peer=peer.key, data_size=decision.data_size,
                          detail=str(detail),
                          evidence=(self._bulk_seen.get(peer.key) or {}).get("evidence"))
        elif decision.reason in ("oversize", "local_echo"):
            self.log.info("skipped %s" % decision.reason, peer=peer.key,
                          uti=decision.uti, bytes=decision.data_size or
                          (len(decision.data) if decision.data else None),
                          detail=decision.detail)
        elif decision.reason == "empty":
            self.log.debug("peer pasteboard empty", peer=peer.key)
        elif decision.reason == "nodata":
            self.log.debug("no inlinable representation", peer=peer.key)
        elif decision.reason == "unchanged":
            self.log.debug("generation unchanged", peer=peer.key,
                           digest=(decision.digest or "")[:12])

    def _save_bulk_evidence(self, peer, pb):
        """Keep what a bulk generation says about its deferred transfer (once per
        generation): the descriptor names the `_continuity._tcp` service that serves the
        bytes. Local state only — it carries device identifiers, so the log gets only the
        file's path. Returns that path, or None."""
        try:
            doc = dict(pasteboard.bulk_evidence(pb), peer=peer.key, address=peer.address,
                       port=peer.port, at=int(time.time()))
            return state.save_bulk_evidence(peer.key, doc)
        except (OSError, TypeError, ValueError) as exc:
            self.log.debug("could not save bulk evidence", error=str(exc))
            return None

    def _notify(self, peer, decision, landed=None):
        if not self.settings["notify"]:
            return
        if decision.reason == "oversize":
            summary = "omclip: %s" % ("file too large" if decision.uti == "public.file-url" else "item too large")
            body = "%s from %s" % (decision.detail, peer.label)
            try:
                subprocess.run(["notify-send", "-u", "critical", "-a", "omclip", summary, body],
                               timeout=3.0, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.SubprocessError):
                pass
            return
        # No clipboard content in a desktop notification. A file mirror names the file and
        # its size — never the `file://` URI's length (that is what `decision.data` is),
        # and never the path: a notification is transient and may sit on a lock screen.
        if landed is not None:
            summary = "omclip: %s" % landed.name
            body = "%s from %s" % (statusmod.format_bytes(landed.bytes), peer.label)

            def _wait_and_open():
                try:
                    res = subprocess.run(
                        ["notify-send", "-a", "omclip", "--action=default=Open", summary, body],
                        capture_output=True, text=True, timeout=60.0, check=False
                    )
                    if res and getattr(res, "returncode", None) == 0 and (res.stdout or "").strip() == "default":
                        try:
                            subprocess.Popen(["xdg-open", self.settings["download_dir"]])
                        except OSError:
                            pass
                except (OSError, subprocess.SubprocessError):
                    pass

            threading.Thread(target=_wait_and_open, daemon=True).start()
        else:
            summary = "omclip: mirrored %s" % (decision.uti or "item")
            body = "%d bytes from %s" % (len(decision.data), peer.label)
            try:
                subprocess.run(["notify-send", "-a", "omclip", summary, body],
                               timeout=3.0, check=False,
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except (OSError, subprocess.SubprocessError):
                pass

    # --------------------------------------------------------------- ble hook

    def on_ble(self, addr, status, counter, tlv):
        """A 0x0c beacon: bring the next poll round forward (rate-limited, best effort).

        The carrier address is only ever informational: BLE addresses rotate (one device can
        even send from two at once), so a beacon is *not* correlated to a peer. Any `0x08`
        announcement shortens the wait for every in-scope peer, which is safe because a
        spurious trigger costs one bounded poll round and nothing else — correctness never
        depends on this path.
        """
        if not ble.clipboard_advertised(status):
            return
        now = time.monotonic()
        if now - self.last_ble_trigger < BLE_RATE_LIMIT_S:
            return
        self.last_ble_trigger = now
        for peer in self.peers:
            if not peer.in_scope:
                continue
            peer.force_fast_until = now + POLL_FAST_WINDOW_S
            peer.next_attempt = 0.0            # due in the next loop pass
        self.log.info("ble handoff 0x0c: polling now", addr=addr,
                      counter=counter, window="%ds" % int(POLL_FAST_WINDOW_S))
        self._wake()

    def _wake(self):
        if self._wake_w is None:
            return
        try:
            self._wake_w.send(b"t")
        except OSError:
            pass

    def _start_ble(self):
        if not self.settings["ble_trigger"]:
            self.ble_backend = "unavailable"
            self.ble_detail = "ble_trigger=false"
            return
        # Check the radio *first*: importing PyGObject/dbus costs ~10 MB of RSS and is
        # pointless when there is no bluetoothd to register with.
        ok, reason = True, "ok"
        health = bluetooth.probe()
        if health.status != bluetooth.OK:
            ok, reason = False, "bluetooth %s: %s" % (health.status, health.detail)
        if ok:
            ok, reason = ble.dependencies()
        if not ok:
            self.ble_backend = "unavailable"
            self.ble_detail = reason
            self.log.warn("BLE trigger unavailable; using timed polling only: %s" % reason)
            return
        self.monitor = ble.BleMonitor(self.on_ble, log=self.log)
        started, info = self.monitor.start()
        if started:
            self.ble_backend = info
            self.ble_detail = None
            self.log.info("ble trigger active", backend=info)
        else:
            self.ble_backend = "unavailable"
            self.ble_detail = info
            self.monitor = None
            # Exactly one warn: never a retry storm.
            self.log.warn("BLE advertisement monitor failed; timed polling only: %s" % info)

    # --------------------------------------------------------------- omdrop

    def _refresh_omdrop(self):
        self.omdrop_status = omdrop.status()

    def _tick_omdrop(self):
        """Retry opening the AWDL window while the phone is in scope and there is none.

        `omdrop on` can fail for reasons that go away (bluetoothd restarted, the radio busy
        with another job), so a failure is retried slowly instead of being forgotten — but
        only when nothing is owned or open, and never more often than OMDROP_RETRY_S.

        A window omclip owns is checked on the same cadence: it can close under us (a
        suspend makes omdrop's supervisor tear the radio down on resume while its user
        timer still runs), and without this the phone stayed unreachable until
        `omclip off; omclip on`.
        """
        if "phone" not in self.scope:
            return
        now = time.monotonic()
        if now < self.omdrop_retry_at:
            return
        self.omdrop_retry_at = now + OMDROP_RETRY_S
        if self.omdrop_owned:
            self._check_owned_window()
            return
        if discovery.awdl_up() is True:
            return
        self._open_omdrop_window()

    def _check_owned_window(self):
        """Reopen the window omclip owns when omdrop says it is gone or its radio collapsed."""
        self._refresh_omdrop()
        doc = self.omdrop_status
        if doc is None or omdrop.window_active(doc):
            return
        self.log.warn("the omdrop window omclip opened has closed; reopening it",
                      mode=doc.get("mode"), visible=doc.get("visible"),
                      reason=doc.get("reason"))
        # `--force`: a collapsed window has no radio to finish a send on, and this is
        # the same call omdrop's own window timer makes.
        omdrop.stop(timeout=OMPDROP_STOP_TIMEOUT, force=True)
        self.omdrop_owned = False
        # omdrop's teardown stopped bluetooth.service and rfkill-blocked the adapter, so
        # the radio has to be brought back before the window (see `_ensure_bluetooth`).
        self.bluetooth_ready = False
        self._open_omdrop_window()

    def _ensure_bluetooth(self):
        """Bring the radio up once per daemon run, before the BLE monitor registers.

        `omdrop` opens its own window later and would also unblock the adapter, but that
        happens *after* `_start_ble()` — and the BLE trigger is what wakes a sleeping
        iPhone, so the adapter has to be usable first.
        """
        # `bluetooth_ready` alone, not ownership: a radio we own can still be taken
        # away (omdrop's teardown stops the unit), and `_check_owned_window` clears
        # `ready` so this brings it back.
        if self.bluetooth_ready:
            return
        ok, owned, message = bluetooth.ensure_started()
        if not ok:
            # One warn per distinct reason, like `omdrop_error`: this is also the retry
            # path (`_tick_omdrop` → `_open_omdrop_window`), not a once-per-run hook.
            if message != self.bluetooth_error:
                self.log.warn("could not bring bluetooth up; the BLE trigger stays off",
                              error=message)
            self.bluetooth_error = message
            return
        self.bluetooth_ready = True
        self.bluetooth_error = None
        if owned:
            self.bluetooth_owned = True
            self.log.info("started bluetooth.service and powered the adapter", owned=True)
        else:
            self.bluetooth_pre_existing = True

    def _release_bluetooth(self):
        """Give the radio back exactly as this run found it.

        Owned → stop the unit and re-block rfkill (this machine's idle baseline). Merely
        pre-existing → put it back: `omdrop`'s own supervisor stops `bluetooth.service`
        when its AWDL window closes, and a service the user was already running has to
        survive `omclip off` (measured 2026-10-13: without this it does not).
        """
        if self.bluetooth_owned:
            ok, message = bluetooth.stop()
            self.log.info("released the bluetooth.service it started", ok=ok, detail=message)
            self.bluetooth_owned = False
            self.bluetooth_ready = False
            return
        if self.bluetooth_pre_existing and not bluetooth.service_active():
            ok, message = bluetooth.ensure_running()
            self.log.info("put back the bluetooth.service it found running", ok=ok,
                          detail=message)

    def _open_omdrop_window(self):
        if "phone" not in self.scope:
            return
        self._ensure_bluetooth()
        self._refresh_omdrop()
        if self.omdrop_status is None:
            self.log.warn("omdrop status unavailable; the iPhone peer will stay unreachable")
            return
        if omdrop.window_active(self.omdrop_status):
            self.log.info("omdrop window already open; leaving it alone")
            return
        if omdrop.radio_collapsed(self.omdrop_status):
            # Someone else's window whose radio is gone: not ours to close. Its own timer
            # ends it, and `_tick_omdrop` opens ours after that.
            message = ("an omdrop window is open but its radio has stopped (reason: %s); "
                       "waiting for it to close" % self.omdrop_status.get("reason"))
            if message != self.omdrop_error:
                self.log.warn(message)
            self.omdrop_error = message
            return
        # Always explicit: a bare `omdrop on` is omdrop's default *10-minute* window
        # (measured: `omdrop watch --window 10m` for an omclip run of `forever`), after
        # which the phone silently went unreachable.
        arg = durationmod.canon(self.window.seconds)          # None → "forever"
        # The radio is already up and owned here (see `_ensure_bluetooth`), so omdrop
        # must not re-probe it: ownership has to stay with the daemon.
        ok, message = omdrop.start(arg, ensure_bluetooth=False)
        if ok:
            self.omdrop_owned = True
            self.omdrop_window = arg
            # The first ownership check waits a full interval: the radio needs a moment.
            self.omdrop_retry_at = time.monotonic() + OMDROP_RETRY_S
            self.omdrop_error = None
            self.log.info("started an omdrop window", window=self.omdrop_window,
                          owned=True)
        else:
            # Kept so the phone peer's `detail` can say *why*, and retried slowly by
            # `_tick_omdrop` — one warn line per distinct error, never a retry storm.
            if message != self.omdrop_error:
                self.log.warn("could not start an omdrop window; the iPhone peer will "
                              "stay unreachable", error=message)
            self.omdrop_error = message

    def _close_omdrop_window(self):
        if not self.omdrop_owned:
            return
        ok, message = omdrop.stop(timeout=OMPDROP_STOP_TIMEOUT)
        self.log.info("closed the omdrop window it opened", ok=ok, detail=message)
        self.omdrop_owned = False

    # --------------------------------------------------------------- status

    def _check_credentials(self, force=False):
        now = time.monotonic()
        if not force and self._creds is not None and now - self.last_creds < CREDENTIAL_REFRESH_S:
            return
        self._creds = [c.as_dict() for c in credentials.check(self.settings["keys_dir"],
                                                              self.settings["identity_dir"])]
        self.last_creds = now
        if not force:
            return
        for item in self._creds:
            if item["status"] in ("expired", "warn"):
                self.log.warn("credential %s: %s" % (item["status"], item["file"]),
                              kind=item["kind"], days_left=item["days_left"])

    def _refresh_health(self, force=False):
        self._check_credentials()
        now = time.monotonic()
        if not force and self._health is not None and now - self.last_health < HEALTH_REFRESH_S:
            return
        self._health = statusmod.live_health(self.settings)
        self.last_health = now

    def current_state(self):
        if self.fatal:
            return "error"
        if any(p.in_scope and p.state in peermod.HEALTHY_STATES for p in self.peers):
            return "on"
        if not self.first_round_done:
            return "starting"
        return "degraded"

    def error_list(self):
        """System-level problems and, while degraded, one line per in-scope peer.

        A partially working setup (mac fine, phone unreachable) is `on`; the phone's
        reason then lives in `peers[].detail` and `peers[].last_error`, not here.
        """
        errors = list(self.fatal)
        if self.identity is None:
            return errors
        if self.last_oversize_error:
            errors.append(self.last_oversize_error)
        if self.current_state() == "degraded":
            for peer in self.peers:
                if peer.in_scope:
                    errors.append("%s: %s" % (peer.key, peer.last_error or peer.detail
                                              or peer.state))
        return errors

    def status_doc(self):
        self._refresh_health()
        # Read at write time: the AEAD backend is a fact about the crypto module that can
        # change mid-run (a call-time libcrypto failure degrades it), unlike ble_backend,
        # which the registration flow sets once.
        crypto_backend, crypto_detail = crypto.aead_backend(), crypto.aead_detail()
        return {
            "schema": statusmod.SCHEMA,
            "version": VERSION,
            "state": self.current_state(),
            "on": True,
            "since": int(self.window.since),
            "expires_at": self.window.expires_at,
            "seconds_left": self.window.seconds_left(),
            "scope": list(self.scope),
            "duration": self.window.duration,
            "stale": False,
            "instance": {
                "pid": os.getpid(),
                "rss_kb": statusmod.proc_rss_kb(os.getpid()),
                "uptime_s": int(time.time() - self.started_at),
                "unit": paths.UNIT_NAME,
                "unit_state": "active",
            },
            "peers": [peer.to_status() for peer in self.peers],
            "clipboard": {
                "mirrored_total": self.mirrored_total,
                "last_mirrored_at": self.last_mirrored_at,
                "last_digest": self.last_digest,
                "last_uti": self.last_uti,
                "last_bytes": self.last_bytes,
                "last_file": self.last_file,
                "last_preview": self.last_preview,
                "skipped": dict(self.counters),
            },
            "health": dict(self._health or {}, bluetooth_owned=self.bluetooth_owned,
                           omdrop_owned=self.omdrop_owned,
                           ble_backend=self.ble_backend, ble_detail=self.ble_detail,
                           crypto_backend=crypto_backend, crypto_detail=crypto_detail),
            "credentials": self._creds or [],
            "errors": self.error_list(),
            "heartbeat": int(time.time()),
            "pid": os.getpid(),
            "started_at": int(self.started_at),
            "bluetooth_owned": self.bluetooth_owned,
            "omdrop_owned": self.omdrop_owned,
            "ble_backend": self.ble_backend,
            "ble_detail": self.ble_detail,
            "crypto_backend": crypto_backend,
            "crypto_detail": crypto_detail,
        }

    def _write_status(self, force=False):
        now = time.monotonic()
        if not force and now - self.last_write < STATUS_WRITE_S:
            return
        try:
            statusmod.write(self.status_doc())
            self.last_write = now
        except OSError as exc:
            self.log.error("status write failed: %s" % exc)

    # --------------------------------------------------------------- shutdown

    def _shutdown(self):
        """Close everything, write a final status, exit 0 inside the 2 s budget."""
        self.log.info("daemon stopping", reason=self.stop_reason or "signal")
        for peer in self.peers:
            peer.close_session()
            if peer.in_scope:
                peer.state = "disabled"
                peer.detail = None
        if self.monitor is not None:
            self.monitor.stop()
        self._close_omdrop_window()
        self._release_bluetooth()
        doc = self.status_doc()
        doc["state"] = "off"
        doc["on"] = False
        doc["peers"] = statusmod.blank_peers(state="disabled", scope=self.scope)
        doc["heartbeat"] = int(time.time())
        try:
            statusmod.write(doc)
        except OSError:
            pass
        state.clear_runtime()
        if self.stop_reason in ("expired", "once"):
            state.clear_desired()
        if self._lock_fd is not None:
            try:
                os.close(self._lock_fd)
            except OSError:
                pass
            self._lock_fd = None
        self.log.close()

    def _acquire_lock(self):
        """One daemon only: a second one exits 0 saying it is already running."""
        paths.ensure_dir(paths.STATE_DIR)
        fd = os.open(paths.LOCK_FILE, os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False
        os.ftruncate(fd, 0)
        os.write(fd, b"%d\n" % os.getpid())
        self._lock_fd = fd
        return True


def _new_stop_event():
    import threading
    return threading.Event()


def _install_signal_handlers(stop_event):
    def handler(signum, _frame):                  # noqa: ARG001
        stop_event.set()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass


def run_daemon(settings):
    """`omclip daemon` — what `omclip.service` runs."""
    logger = logmod.Logger(paths.LOG_FILE, level=settings["log_level"])
    for warning in settings.warnings:
        logger.warn("settings: %s" % warning)
    for warning in logger.warnings:
        print("omclip daemon: %s" % warning, file=os.sys.stderr)
    return Daemon(settings, logger).run()
