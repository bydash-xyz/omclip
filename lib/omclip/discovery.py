"""Peer discovery: unicast/multicast mDNS for `_companion-link._tcp`, AWDL neighbours.

A stdlib mDNS resolver, which is the only approach that works on this machine:
**avahi is configured to deny `awdl0`**
(`deny-interfaces=awdl0,radiotap0,wg-oci`), so `avahi-browse` cannot see an iPhone at
all, and multicast to `ff02::fb` on `awdl0` gets no answers — only *unicast* does.
`avahi-browse` is therefore at most a LAN convenience fallback; the primary path is
this resolver.

* Mac (LAN): multicast `_companion-link._tcp.local` PTR on the LAN interface, then the
  SRV/TXT for the instance; if nothing answers, the configured `mac_host`/`mac_port`.
* iPhone (AWDL): omdrop's live AWDL peer table (`/run/awdl-discoverable/peers.json`) gives
  the link-local peers actually in range — `ip -6 neigh show dev awdl0` is only the fallback,
  because it accumulates PERMANENT entries for every device ever seen (31 here, the iPhone
  14th) — then **unicast** SRV/TXT queries to all of them at once for the **ephemeral**
  port, re-resolved on every reconnect (iOS mints a new port whenever the service restarts).
"""

import json
import re
import socket
import struct
import subprocess
import time

MDNS_V4 = "224.0.0.251"
MDNS_V6 = "ff02::fb"
PORT = 5353

TYPE_PTR, TYPE_TXT, TYPE_SRV, TYPE_AAAA, TYPE_A = 12, 16, 33, 28, 1

COMPANION = "_companion-link._tcp.local"
DEFAULT_SERVICES = (COMPANION, "_airdrop._tcp.local", "_apple-mobdev._tcp.local")

_TOOL_TIMEOUT = 4.0


class Instance:
    """A resolved DNS-SD instance.

    `address` is the A/AAAA target when the packet carried one — the same service type
    is advertised by several devices (an Apple TV answered here alongside the Mac), so a
    caller that knows the address it wants must be able to match on it.
    """

    def __init__(self, service, name, host, port, txt="", address="", addresses=None):
        self.service = service
        self.name = name
        self.host = host
        self.port = int(port) if port else None
        self.txt = txt
        self.addresses = list(addresses or ([address] if address else []))
        self.address = address or (self.addresses[0] if self.addresses else "")

    def __repr__(self):
        return "Instance(%s, %s, %s:%s, %s)" % (self.service, self.name, self.host,
                                                self.port, self.address)


# --------------------------------------------------------------------------
# wire format
# --------------------------------------------------------------------------

def encode_name(name):
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode()
    return out + b"\x00"


def decode_name(data, offset):
    """Decode a (possibly compressed) DNS name; returns (name, next_offset)."""
    labels, jumped, nxt = [], False, offset
    while True:
        length = data[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:                       # compression pointer
            pointer = struct.unpack(">H", data[offset:offset + 2])[0] & 0x3FFF
            if not jumped:
                nxt = offset + 2
            offset, jumped = pointer, True
            continue
        labels.append(data[offset + 1:offset + 1 + length].decode("utf-8", "replace"))
        offset += 1 + length
    return ".".join(labels), (nxt if jumped else offset)


def build_query(name, qtype):
    return (struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
            + encode_name(name) + struct.pack(">HH", qtype, 1))


def parse_records(data, origin=""):
    """Collect answers/Additional from one mDNS packet → [(name, kind, value, ttl)]."""
    out = []
    try:
        qd, an, ns, ar = struct.unpack(">HHHH", data[4:12])
    except struct.error:
        return out
    offset = 12
    for _ in range(qd):
        _, offset = decode_name(data, offset)
        offset += 4
    for _ in range(an + ns + ar):
        name, offset = decode_name(data, offset)
        if offset + 10 > len(data):
            return out
        rtype, rclass, ttl, rdlen = struct.unpack(">HHIH", data[offset:offset + 10])
        offset += 10
        rdata = data[offset:offset + rdlen]
        if rtype == TYPE_SRV and len(rdata) >= 6:
            priority, weight, port = struct.unpack(">HHH", rdata[:6])
            target, _ = decode_name(data, offset + 6)
            out.append((name, "SRV", "%s:%d" % (target, port), ttl))
        elif rtype == TYPE_TXT:
            pairs, i = [], 0
            while i < len(rdata):
                ln = rdata[i]
                pairs.append(rdata[i + 1:i + 1 + ln].decode("utf-8", "replace"))
                i += 1 + ln
            out.append((name, "TXT", " ".join(pairs), ttl))
        elif rtype == TYPE_AAAA and len(rdata) == 16:
            addr = socket.inet_ntop(socket.AF_INET6, rdata)
            out.append((name, "AAAA", "%s%%%s" % (addr, origin) if origin else addr, ttl))
        elif rtype == TYPE_A and len(rdata) == 4:
            out.append((name, "A", socket.inet_ntop(socket.AF_INET, rdata), ttl))
        elif rtype == TYPE_PTR:
            target, _ = decode_name(data, offset)
            out.append((name, "PTR", target, ttl))
        offset += rdlen
    return out


def instances_from_records(records, services=DEFAULT_SERVICES):
    """Resolve PTR/SRV/TXT/A/AAAA tuples into `Instance` objects."""
    ptrs, srvs, txts, addrs = [], {}, {}, {}
    for name, kind, value, _ttl in records:
        if kind == "PTR":
            ptrs.append(value)
        elif kind == "SRV":
            srvs[name] = value
        elif kind == "TXT":
            txts[name] = value
        elif kind in ("A", "AAAA"):
            addrs.setdefault(name, []).append(value.split("%")[0])
    out = []
    for instance in ptrs:
        target = srvs.get(instance)
        if not target:
            continue
        host, _, port = target.rpartition(":")
        service = next((s for s in services if s in instance), COMPANION)
        out.append(Instance(service, instance.split(".")[0], host, int(port),
                            txts.get(instance, ""), addresses=addrs.get(host) or []))
    return out


# --------------------------------------------------------------------------
# queries
# --------------------------------------------------------------------------

def query(iface, names, timeout=3.0, unicast=None):
    """Send PTR+SRV+TXT queries on one interface and collect records for `timeout`.

    `unicast` (an address string) sends the queries to that peer:5353 instead of to
    the multicast group — the only mode that works on `awdl0` here.
    """
    v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    records = []
    try:
        v6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
        scope = socket.if_nametoindex(iface)
        v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, scope)
        try:
            v6.bind(("::", PORT))
        except OSError:
            v6.bind(("::", 0))
        if not unicast:
            try:
                v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
                              socket.inet_pton(socket.AF_INET6, MDNS_V6)
                              + struct.pack("@I", scope))
            except OSError:
                pass
        v6.settimeout(0.5)
        for name in names:
            for qname, qtype in ((name, TYPE_PTR), (name, TYPE_SRV), (name, TYPE_TXT)):
                packet = build_query(qname, qtype)
                try:
                    if unicast:
                        v6.sendto(packet, (unicast, PORT, 0, scope))
                    else:
                        v6.sendto(packet, (MDNS_V6, PORT, 0, scope))
                except OSError:
                    return records
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, _ = v6.recvfrom(9000)
            except (socket.timeout, OSError):
                continue
            records.extend(parse_records(data, iface))
    finally:
        v6.close()
    return records


def iface_v4_address(iface):
    """The interface's IPv4 address (needed for IP_MULTICAST_IF), or None."""
    rc, out = run(["ip", "-o", "-4", "addr", "show", "dev", iface], timeout=2.0)
    if rc != 0:
        return None
    match = re.search(r"\binet\s+(\d+\.\d+\.\d+\.\d+)", out)
    return match.group(1) if match else None


def query_v4(iface, names, timeout=2.0):
    """IPv4 multicast DNS-SD query (224.0.0.251) on one interface.

    Needed because Apple devices answer the `_companion-link` browse over IPv4 link-local
    multicast here: the IPv6 query alone found nothing on the LAN while the IPv4 one found
    the Mac (and an Apple TV) immediately.
    """
    address = iface_v4_address(iface)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    records = []
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
        if address:
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF,
                                socket.inet_aton(address))
            except OSError:
                pass
        try:
            sock.bind(("", PORT))
        except OSError:
            sock.bind(("", 0))
        try:
            group = socket.inet_aton(MDNS_V4)
            if address:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                group + socket.inet_aton(address))
        except OSError:
            pass
        sock.settimeout(0.5)
        for name in names:
            for qname, qtype in ((name, TYPE_PTR), (name, TYPE_SRV), (name, TYPE_TXT)):
                try:
                    sock.sendto(build_query(qname, qtype), (MDNS_V4, PORT))
                except OSError:
                    return records
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                data, _ = sock.recvfrom(9000)
            except (socket.timeout, OSError):
                continue
            records.extend(parse_records(data, iface))
    finally:
        sock.close()
    return records


def resolve_companion_link(iface, timeout=3.0, unicast=None):
    """All `_companion-link._tcp` instances reachable on `iface`.

    `unicast` (the AWDL case) is a single IPv6 unicast query: multicast does not work on
    `awdl0`. Otherwise both families are queried — IPv4 multicast answers for LAN peers,
    IPv6 multicast for anything dual-stacked.
    """
    if unicast:
        return instances_from_records(query(iface, (COMPANION,), timeout=timeout,
                                            unicast=unicast), (COMPANION,))
    # IPv4 first and with the *whole* window: the records that matter (the A record for
    # the SRV target) arrive in later packets, and IPv6 multicast returned nothing at all
    # on this LAN. The IPv6 pass is only a fallback.
    records = query_v4(iface, (COMPANION,), timeout=timeout)
    instances = instances_from_records(records, (COMPANION,))
    if instances:
        return instances
    records += query(iface, (COMPANION,), timeout=min(1.5, timeout))
    return instances_from_records(records, (COMPANION,))


def _strip_scope(address):
    return address.split("%", 1)[0]


def query_unicast_many(iface, names, addresses, timeout=4.0, resend_after=1.5, until=None,
                       port=PORT):
    """Unicast-query every address from **one** socket → {address: records}.

    One socket, not one per address: each would bind :5353 with SO_REUSEADDR and a unicast
    answer lands on only one of them, so parallel `query()` calls could swap answers. Replies
    are attributed by their source address. Addresses still silent after `resend_after` are
    asked again — measured 2026-10-13, the iPhone ignored the first query (no answer within
    4 s) and answered the repeat. Returns once every address answered, `until(results)` is
    true, or at `timeout`.
    """
    addresses = list(dict.fromkeys(addresses))
    results = {}
    if not addresses:
        return results
    v6 = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        v6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        scope = socket.if_nametoindex(iface)
        try:
            v6.bind(("::", PORT))
        except OSError:
            v6.bind(("::", 0))
        v6.settimeout(0.25)
        packets = [build_query(name, qtype) for name in names
                   for qtype in (TYPE_PTR, TYPE_SRV, TYPE_TXT)]

        def ask(targets):
            for address in targets:
                for packet in packets:
                    try:
                        v6.sendto(packet, (address, port, 0, scope))
                    except OSError:
                        break

        ask(addresses)
        start = time.monotonic()
        resent = False
        while time.monotonic() - start < timeout:
            if not resent and time.monotonic() - start >= resend_after:
                resent = True
                ask([a for a in addresses if a not in results])
            try:
                data, peer = v6.recvfrom(9000)
            except (socket.timeout, OSError):
                continue
            source = _strip_scope(peer[0])
            if source in addresses:
                results.setdefault(source, []).extend(parse_records(data, iface))
                if len(results) == len(addresses) or (until and until(results)):
                    break
    finally:
        v6.close()
    return results


def resolve_companion_link_many(iface, addresses, timeout=4.0, resend_after=1.5,
                                accept=None):
    """`_companion-link` instances per AWDL address → {address: [Instance]} (silent
    addresses are absent). Stops early once some instance satisfies `accept(address,
    instance)` — the rest of the window is only spent while nothing usable has answered."""
    def resolved(results):
        return {address: instances_from_records(records, (COMPANION,))
                for address, records in results.items()}

    def until(results):
        return any(accept(address, inst) for address, insts in resolved(results).items()
                   for inst in insts if inst.port)
    return resolved(query_unicast_many(iface, (COMPANION,), addresses, timeout=timeout,
                                       resend_after=resend_after,
                                       until=until if accept else None))


# --------------------------------------------------------------------------
# system facts
# --------------------------------------------------------------------------

def run(argv, timeout=_TOOL_TIMEOUT):
    """Run a helper and return (rc, stdout). Never raises."""
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return 127, ""
    return proc.returncode, proc.stdout.decode("utf-8", "replace")


def lan_interface(host=None):
    """The interface the kernel would use to reach `host` (one `ip route get`)."""
    if host:
        rc, out = run(["ip", "-o", "route", "get", host], timeout=2.0)
        if rc == 0:
            match = re.search(r"\bdev\s+(\S+)", out)
            if match:
                return match.group(1)
    rc, out = run(["ip", "-o", "route", "show", "default"], timeout=2.0)
    if rc == 0:
        match = re.search(r"\bdev\s+(\S+)", out)
        if match:
            return match.group(1)
    return None


# `ip -6 neigh show` and `ip -6 neigh show dev awdl0` print *different* columns: filtering by
# device omits the `dev <iface>` field (measured 2026-10-13 — assuming otherwise silently
# yielded zero neighbours), and entries may carry trailing whitespace.
_NEIGH = re.compile(r"^(?P<addr>\S+)(?:\s+dev\s+(?P<dev>\S+))?"
                    r"(?:\s+lladdr\s+(?P<mac>\S+))?(?:\s+(?P<state>[A-Z]+))?\s*$")


def parse_neighbors(text):
    """`ip -6 neigh show [dev X]` → [(address, mac, state)].

    Both shapes are accepted (with and without the `dev <iface>` column), the interface name
    is ignored (the caller already chose it) and entries with no lladdr/state still parse.
    """
    out = []
    for line in text.splitlines():
        match = _NEIGH.match(line.strip())
        if match:
            out.append((match.group("addr"), match.group("mac"), match.group("state")))
    return out


def awdl_neighbors(iface="awdl0"):
    """Link-local peering partners on the AWDL interface (the iPhone's address)."""
    rc, out = run(["ip", "-6", "neigh", "show", "dev", iface], timeout=2.0)
    if rc != 0:
        return []
    return [addr for addr, _mac, _state in parse_neighbors(out) if addr.startswith("fe80:")]


#: omdrop's AWDL daemon keeps the peers it currently hears here (root-owned, world-readable).
AWDL_PEERS_FILE = "/run/awdl-discoverable/peers.json"
#: A peer not heard from for this long is gone (the file is rewritten every few seconds).
AWDL_PEER_MAX_AGE_S = 60.0


def link_local_from_mac(mac):
    """EUI-64 link-local address for a MAC (`6e:5f:…` → `fe80::6c5f:…ff:fe…`), or None."""
    try:
        octets = [int(part, 16) for part in mac.split(":")]
    except (AttributeError, ValueError):
        return None
    if len(octets) != 6 or any(o < 0 or o > 255 for o in octets):
        return None
    eui = [octets[0] ^ 0x02] + octets[1:3] + [0xFF, 0xFE] + octets[3:]
    # Through inet_ntop so it compares equal to what `ip neigh` and recvfrom print.
    return socket.inet_ntop(socket.AF_INET6, bytes([0xFE, 0x80] + [0] * 6 + eui))


def awdl_live_peers(path=None, now=None, max_age=AWDL_PEER_MAX_AGE_S):
    """Link-local addresses of the AWDL peers omdrop hears *now*, strongest signal first.

    None when the table is unavailable (no omdrop window, older omdrop) — the caller then
    falls back to the neighbour table; [] means it is there and nobody is in range.
    """
    try:
        with open(path or AWDL_PEERS_FILE, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(doc, dict):
        return None
    now = time.time() if now is None else now
    live = []
    for key, peer in doc.items():
        if not isinstance(peer, dict):
            continue
        seen = peer.get("last_seen")
        if not isinstance(seen, (int, float)) or now - seen > max_age:
            continue
        address = link_local_from_mac(peer.get("addr") or key)
        if address:
            rssi = peer.get("rssi")
            live.append((rssi if isinstance(rssi, (int, float)) else -999, address))
    live.sort(key=lambda item: -item[0])
    return [address for _rssi, address in live]


def awdl_up(iface="awdl0"):
    """AWDL link state: True = up, False = down/absent, None = cannot tell.

    No `awdl0` at all means no `omdrop` window is open, which is the normal state
    here — that is `down`, not `unknown`.
    """
    try:
        with open("/sys/class/net/%s/operstate" % iface, "r", encoding="utf-8") as fh:
            state = fh.read().strip()
    except FileNotFoundError:
        return False
    except OSError:
        return None
    return state in ("up", "unknown")


#: avahi-browse wants the service *without* the `.local` domain: passing
#: `_companion-link._tcp.local` silently matches nothing.
AVAHI_SERVICE = "_companion-link._tcp"


def avahi_browse(service=AVAHI_SERVICE, timeout=4.0):
    """LAN-only fallback: `avahi-browse -rtp` (avahi denies awdl0, so never for the phone).

    Output is `=;iface;proto;name;service;domain;host;address;port;txt…`.
    """
    rc, out = run(["avahi-browse", "-rtp", service], timeout=timeout)
    if rc != 0:
        return []
    instances = []
    for line in out.splitlines():
        if not line.startswith("="):
            continue
        parts = line.split(";")
        if len(parts) < 10:
            continue
        instances.append(Instance(service, parts[3], parts[6], parts[8] or None,
                                  " ".join(parts[9:]), addresses=[parts[7]]))
    return [i for i in instances if i.port]


def first_instance(instances, prefer_service=COMPANION):
    """Pick the companion-link instance with a port, else any with a port."""
    for inst in instances:
        if inst.service == prefer_service and inst.port:
            return inst
    for inst in instances:
        if inst.port:
            return inst
    return None


def pick_by_host(instances, host, prefer_service=COMPANION):
    """Pick an instance by its SRV target host name (used once an address match taught us
    which host name belongs to the peer — the A/AAAA records are not always present)."""
    if not host:
        return None
    for inst in instances:
        if inst.port and inst.host == host and inst.service == prefer_service:
            return inst
    return None


def pick_instance(instances, address=None, prefer_service=COMPANION):
    """Pick an instance, preferring one that answers on `address`.

    Several devices advertise `_companion-link` (an Apple TV does on this LAN); when the
    caller knows which address it wants, an instance for a *different* address must be
    ignored rather than used as a port source.
    """
    if address:
        for inst in instances:
            if inst.port and address in inst.addresses and inst.service == prefer_service:
                return inst
        return None
    return first_instance(instances, prefer_service)
