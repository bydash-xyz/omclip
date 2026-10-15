#!/usr/bin/env python3
"""Probe the transfer a bulk-mode pasteboard defers to. Read-only research tool.

Usage (right after copying something large — a photo, a Safari selection — on the Mac or
iPhone while `omclip on` runs, so the daemon has written an evidence file):

    python3 tools/bulk_probe.py                 # newest ~/.local/state/omclip/bulk/*.json
    python3 tools/bulk_probe.py EVIDENCE.json

It answers the open question from 2026-10-13: is the descriptor's `bonjour_name` the
`_continuity._tcp` instance the peer advertises (seen on the Mac as `97b1f7346d19` on :8771,
a TLS server with an Apple ID certificate that requests a client certificate)? It then
completes a mutual-TLS handshake with the omdrop identity and records only what the server
sends on its own. It sends no application data, writes nothing, and changes nothing.
"""

import glob
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(HERE), "lib"))

from omclip import discovery, paths  # noqa: E402

CONTINUITY = "_continuity._tcp.local"


def newest_evidence():
    files = sorted(glob.glob(os.path.join(paths.BULK_DIR, "*.json")))
    return files[-1] if files else None


def lan_continuity():
    """avahi's view of `_continuity._tcp` on the LAN → [(name, host, address, port)]."""
    try:
        out = subprocess.run(["avahi-browse", "-rpt", "_continuity._tcp"], capture_output=True,
                             timeout=8, check=False).stdout.decode("utf-8", "replace")
    except (OSError, subprocess.SubprocessError):
        return []
    found = []
    for line in out.splitlines():
        parts = line.split(";")
        if parts[0] == "=" and len(parts) >= 9:
            name = re.sub(r"\\(\d{3})", lambda m: chr(int(m.group(1))), parts[3])
            found.append((name, parts[6], parts[7], int(parts[8])))
    return found


def awdl_continuity(address):
    """Unicast `_continuity._tcp` query to an AWDL peer → [(name, host, address, port)]."""
    answers = discovery.query_unicast_many("awdl0", (CONTINUITY,), [address], timeout=4.0)
    insts = discovery.instances_from_records(answers.get(address, []), (CONTINUITY,))
    return [(i.name, i.host, "%s%%awdl0" % address, i.port) for i in insts if i.port]


def tls_probe(address, port, cert, key, listen_s=5.0):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE           # Apple Application Integration CA, not ours
    ctx.load_cert_chain(cert, key)
    report = {"address": address, "port": port}
    host, _, scope = address.partition("%")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    target = (host, port, 0, socket.if_nametoindex(scope)) if scope else (host, port)
    raw = socket.socket(family, socket.SOCK_STREAM)
    raw.settimeout(6)
    try:
        raw.connect(target)
        with ctx.wrap_socket(raw) as tls:
            report["tls"] = {"version": tls.version(), "cipher": tls.cipher()[0]}
            der = tls.getpeercert(binary_form=True)
            report["server_cert_bytes"] = len(der) if der else 0
            tls.settimeout(0.5)
            got, end = b"", time.monotonic() + listen_s
            while time.monotonic() < end and len(got) < 4096:
                try:
                    chunk = tls.recv(4096)
                except (socket.timeout, ssl.SSLWantReadError):
                    continue
                if not chunk:
                    report["server_closed"] = True
                    break
                got += chunk
            report["server_sent_unprompted"] = {"bytes": len(got), "hex": got[:512].hex()}
    except (OSError, ssl.SSLError) as exc:
        report["error"] = "%s: %s" % (type(exc).__name__, exc)
    finally:
        raw.close()
    return report


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else newest_evidence()
    if not path:
        print(json.dumps({"error": "no evidence file yet: copy something large on the Mac "
                                   "or iPhone while `omclip on` runs"}))
        return 1
    with open(path, encoding="utf-8") as fh:
        ev = json.load(fh)
    descriptor = ev.get("descriptor") or {}
    bonjour = descriptor.get("bonjour_name")
    services = lan_continuity()
    if ev.get("peer") == "phone" and ev.get("address"):
        services += awdl_continuity(ev["address"])
    match = [s for s in services if bonjour and s[0] == bonjour]
    keys = os.path.expanduser("~/.omdrop/keys")
    report = {"evidence": path, "peer": ev.get("peer"), "data_size": ev.get("data_size"),
              "bonjour_name": bonjour, "author_data_keys": sorted(
                  (descriptor.get("author_data") or {}).keys()),
              "continuity_services": [{"name": n, "host": h, "address": a, "port": p}
                                      for n, h, a, p in services],
              "bonjour_name_matches_a_service": bool(match)}
    if match:
        _n, _h, address, port = match[0]
        report["probe"] = tls_probe(address, port, os.path.join(keys, "certificate.pem"),
                                    os.path.join(keys, "key.pem"))
    print(json.dumps(report, indent=1))
    return 0


if __name__ == "__main__":
    sys.exit(main())
