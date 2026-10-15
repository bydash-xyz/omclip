# omclip — direct Apple Universal Clipboard for Omarchy

Mirror the Air's Wayland clipboard with an Apple device's pasteboard, with no Tether, no
Apple relay, no app on the iPhone, and no Mac in the middle:

```bash
omclip on              # start mirroring the Mac (LAN) and the iPhone (AWDL) until `omclip off`
omclip status          # state, peers, last generation, health, credentials
omclip off             # stop, release the AWDL window if we opened it
```

`omclip` speaks `rapportd`/companion-link as this machine (Pair-Verify, encrypted OPACK,
`com.apple.handoff.payload-request`) and puts what it fetches on the Wayland clipboard with
`wl-copy`. It is a standalone Python package based on Apple Continuity protocol
reverse-engineering; credentials (`certificate.pem`, `key.pem`, `rapport_identity.json`,
`rapport_ids.json`) are read in place from their respective directories (`keys_dir`,
`identity_dir`) and never copied into this repository.

The bar/panel widget is a separate deliverable: see [`docs/ui.md`](docs/ui.md) for the panel
and [docs/status-schema.md](docs/status-schema.md) for the JSON it renders.

## What works today

| | status |
|---|---|
| **Mac → Air** inline pasteboards (≤ ~10 KB) | ✅ **live-verified end to end, 2026-10-13**: with a real small plain-text copy made on the Mac, a Mac-only run (`omclip on --mac`, a flag since removed) mirrored a 77-byte `public.utf8-plain-text` generation (`mirrored: true`, `reason: "mirror"`, digest `2b93a955…`) about 3 s after `on`, and `wl-paste` returned the Mac's exact text; also verified by the reference client and offline with a real clipboard in `tests/test_e2e_clipboard.py` (see journal §7) |
| **Mac → Air** bulk pasteboards (> ~10 KB) | ✅ **live-verified end to end, 2026-10-14**: the daemon resolved the descriptor's `_continuity._tcp` instance, fetched a 308686-byte payload over the companion stream, mirrored its `public.utf8-plain-text` slice, requested the copied file's body and landed it (`stockblob-l2m.bin`, 2 000 000 B, sha256 `c71f8c39…`, offered as `text/uri-list`). One fetch per generation — the same descriptor on the next poll is `unchanged` (see *Bulk transfer: how it works*) |
| **iPhone → Air** over AWDL | ✅ **live-verified, 2026-10-13 21:32**: found among omdrop's live AWDL peers (`fe80::6c5f:a3ff:fe96:4a3f`, ephemeral port 55289), authenticated, and two real iPhone copies (5 B, 6 B) mirrored within a poll. Needs the iPhone unlocked; a locked phone stops answering and is reported `locked` |
| **Air → Apple** (reverse) | ❌ not built (needs our own Handoff `0x0c` announcement and a payload-request listener) |
| continuous sync | ✅ daemon with one session per peer, adaptive polling, reconnect backoff, echo/generation suppression; the omdrop window it owns is re-checked every 60 s and reopened after it closes (e.g. after a suspend) |
| BLE `0x0c` trigger | ✅ registers (`ble_backend: monitor`) and received a real beacon, 2026-10-13; an early poll caused by a clipboard beacon is not yet observed |

## Credentials

`omclip` does not ship, generate or extract credentials, and the extraction tooling is **not**
part of this repository. It authenticates as one of *your own* Apple devices, so it needs that
device's material, extracted by you from your own macOS install on the same Apple ID:

| setting | files | what they are |
|---|---|---|
| `identity_dir` | `rapport_identity.json`, `rapport_ids.json` | the Rapport identity (`edSK`/`edPK`/`dIRK`, OPACK) and the IDS device ID announced as `_idsID` |
| `keys_dir` | `certificate.pem`, `key.pem`, `validation_record.cms` | the AirDrop certificate, its key and the Apple validation record (also used by `omdrop`) |

Treat every one of these as a secret: they let a machine act as your device toward your other
devices. Keep them `chmod 600`, never commit them (this repo's `.gitignore` refuses the usual
names), and re-extract when `omclip status` reports them `warn`/`expired`.

How you obtain them is out of scope for `omclip` and is your responsibility on your own
hardware. The AirDrop trio (`certificate.pem`/`key.pem`/`validation_record.cms`) can be pulled
from your Mac's keychain with [`seemoo-lab/airdrop-keychain-extractor`](https://github.com/seemoo-lab/airdrop-keychain-extractor)
(GPL-3.0; requires relaxing SIP/AMFI — restore them afterward); the Rapport identity
(`rapport_identity.json`/`rapport_ids.json`) is read from the same `com.apple.rapport*` keychain
groups. See the [Disclaimer](#disclaimer) before you do any of this.

## Install

```bash
./install.sh              # or: omclip install
omclip install --json     # same, machine-readable
```

That writes `~/.config/systemd/user/omclip.service` and symlinks `~/.local/bin/omclip` to
this repo's `bin/omclip`, then runs `systemctl --user daemon-reload`. The unit is **not**
enabled at boot and has no `[Install]` section: `omclip on` starts it, `omclip off` stops it.
`./uninstall.sh` (or `omclip uninstall`) removes the unit and the symlink and keeps your
settings and state.

Dependencies: `wl-clipboard`, a Wayland session, `openssl`, and `omdrop` (only for the phone
peer). The BLE trigger additionally wants `python-gobject`/`python-dbus` — all optional, see
below. Python 3.11+ standard library otherwise; nothing is installed into site-packages.

## Commands

```
omclip on [DURATION] [--json]
omclip off [--json]          omclip toggle [--json]
omclip status [--json]       omclip peers [--json]      omclip doctor [--json]
omclip log [-n N] [--json] [--follow]
omclip config [list|get KEY|set KEY VALUE] [--json]
omclip install | uninstall | version | daemon
```

* `DURATION`: a bare integer is **minutes** (`on 10` = 10 minutes), or `30s`, `10m`, `1h`,
  `forever` (the default), `once` (stop after the first successful mirror).
* Every `on` mirrors **both** peers — the Mac over the LAN and the iPhone over AWDL. There is
  no scope switch on the CLI or in the panel: mirroring one peer and not the other only ever
  produced a half-synced copy, and picking the Mac by hand made the Mac's own AWDL
  advertisement show up a second time as "phone". `omclip on` starts `omdrop on <duration>`
  itself when no AWDL window is open, recording that it owns the window, so `omclip off`
  closes only what it opened. The duration is always explicit (`forever` included: a bare
  `omdrop on` is omdrop's 10-minute default), and the owned window is re-checked every 60 s —
  when it has closed, or `omdrop status` shows the radio collapsed (`visible: false` with
  `reason: expired`, which is what a suspend longer than omdrop's own window leaves behind),
  the daemon runs `omdrop off --force`, brings Bluetooth back and reopens it. Someone else's
  collapsed window is left alone and named in the phone peer's `detail`.
* Every `--json` command prints exactly one JSON object and exits 0; a stopped or missing
  daemon is not an error. Mutating commands print `{"ok":true,…}` / `{"ok":false,"error":"…"}`
  and exit 1 on failure. Human mode prints prose on stdout and errors on stderr.
* `status --json` never opens a peer connection and returns in well under 3 s (measured
  0.42 s here); health and credential expiry are probed live every call.

## Configuration

`~/.config/omclip/settings`, `key=value`, validated on load and by `config set` (a bad value
falls back to its default, is reported, and never crashes the daemon):

| key | default | notes |
|---|---|---|
| `scope` | `both` | accepted for compatibility; **every run is `both`** — the daemon mirrors the Mac and the iPhone together and the CLI has no scope flag |
| `duration` | `forever` | settings dialect: a bare integer is **seconds**, or `forever` |
| `mac_host` | `localhost` | where the Mac's `rapportd` is reachable |
| `mac_port` | `49152` | used when mDNS cannot confirm the port |
| `phone_address` | *(empty)* | empty = ask the AWDL peers omdrop hears live (`/run/awdl-discoverable/peers.json`), else `ip -6 neigh show dev awdl0` |
| `poll_seconds` | `2` | cadence while a peer was seen in the last 5 minutes, and for 60 s after a BLE trigger |
| `idle_poll_seconds` | `20` | cadence when nothing has moved for 5 minutes |
| `locked_poll_seconds` | `30` | cadence while the iPhone is locked |
| `max_bytes` | `268435456` | oversize guard: bigger items are skipped, not buffered |
| `ble_trigger` | `true` | use the `0x0c` BLE announcement to poll immediately (optional, see below) |
| `preview` | `true` | keep a ≤160-char text preview in `status.json` (never in the log) |
| `notify` | `false` | `notify-send` on a newly mirrored item |
| `log_level` | `info` | `error`\|`warn`\|`info`\|`debug` |
| `identity_dir` | `~/.config/omclip/identity` | read-only source of `rapport_identity.json` + `rapport_ids.json` |
| `keys_dir` | `~/.omdrop/keys` | AirDrop identity (certificate, key, validation record) |
| `download_dir` | `~/Downloads` | where the body of a copied **file** lands when the bulk transfer delivers it, the same directory `omdrop` drops into. Settable (`omclip config set download_dir /some/absolute/path`, absolute only). Streamed, capped by `max_bytes`, never overwriting an existing name (`IMG_1739 (1).HEIC`) |

## How it works

* **One session per peer, always.** `rapportd` accepts a second authenticated connection from
  the same identity and then closes the first (measured), so the daemon owns exactly one
  socket per peer, closes before reconnecting, and never probes out of band. `flock` on
  `~/.local/state/omclip/lock` makes a second daemon exit 0 immediately.
* **Bounded requests.** One receive loop per session matches the `_x` echo under one absolute
  deadline (≤ 6 s), buffers unsolicited frames (`_systemInfo` reply, `_systemInfoUpdate`,
  handoff events) instead of dropping them, and treats EOF/reset/channel-desync as
  "peer gone" → clean close → backoff 1/2/4/8/16/30 s ±20 % jitter → re-authenticate → re-announce
  `_systemInfo` (mandatory before every payload request). A session with no successful exchange
  for 30 s is recycled.
* **Generation tracking.** digest = `sha256(uti + b"\x00" + representation bytes)`; the same
  digest is skipped as `unchanged`. Bulk items are detected by `DataSize > len(extraData)` —
  *not* by `ExtraTypeKey`, because iOS sends `2` for rich-but-fully-inlined pasteboards — and
  the 324-byte descriptor is never sliced as if it were payload.
* **Echo suppression.** Before `wl-copy` the current local selection is read (best-effort,
  size-capped) and skipped when byte-identical, and a small LRU of digests we wrote ourselves
  is never re-mirrored. Both count as `local_echo`.
* **Adaptive polling, cheap by construction.** No busy loop: the loop sleeps in `select` and
  writes `status.json` at ~1 Hz. Idle cadence is 20 s, 30 s while the iPhone is locked. RSS
  peaks at ~22 MB (systemd `MemoryPeak`), i.e. inside the 40 MB budget; the Python reference
  client is what it is, but nothing here allocates per poll beyond a bounded archive.
* **Honest states.** No reachable peer while the unit is on is `degraded` with the reasons in
  `errors` — there is no state where it claims to be mirroring and is not. The status document
  is written atomically (tmp + `os.replace`) with a heartbeat; `omclip status` flags
  `stale: true` when the unit is active but the heartbeat is older than 10 s.

### The BLE trigger is optional (measured on this machine)

A Handoff `0x0c` announcement whose status byte is `0x08` means "clipboard available", so
hearing one lets `omclip` poll immediately instead of waiting out the cadence. The listener
needs BlueZ's `org.bluez.AdvertisementMonitor1` over D-Bus with PyGObject — neither is stdlib:

* `omclip on` brings the radio up itself when the phone is in scope: it unblocks the adapter,
  starts `bluetooth.service` if it was inactive, and powers it on *before* the monitor tries to
  register (`health.bluetooth_owned: true` records that `omclip` is the one that must release
  it again). A service that was already running is never touched and never owned.
* The trigger works on this machine (fixed 2026-10-13). bluetoothd logs `Adv Monitor Manager
  created with supported features:0x00000000` — no controller offload — and then monitors in
  software over its passive scan. `RegisterMonitor` used to die with
  `org.freedesktop.DBus.Error.NoReply`; that was omclip's own deadlock, not the controller:
  bluetoothd calls the app's `GetManagedObjects` before it replies, and the call was made
  blocking before the GLib loop that serves it ran. It is now asynchronous with the loop
  running, `ble_backend` is `"monitor"`, and a real `0x0c` beacon was received. Measured
  cost: bluetoothd ~0.2 % CPU and 0 ticks in omclip's BLE thread over 30 s, and the
  daemon's cost is the same with the trigger off — the poll loop is what costs, and its
  single hot item used to be pure-python ChaCha20 (see *ChaCha20-Poly1305* below: that item
  is now 0.002 % of one core per answering peer instead of 0.166 %).
* If the bindings are missing, if the adapter refuses (`or_patterns` absent), or if
  `RegisterMonitor` fails, the result is the same: **one** warning, timed polling forever
  after, and the reason in `health`. No retry storm. There is deliberately no
  discovery-mode fallback — an active scan costs 2-5 % CPU and fights `omdrop`'s advertiser
  for the shared 2.4 GHz antenna.
* BLE addresses rotate, so the trigger is never used to identify a peer: any `0x08`
  announcement brings the next poll round forward (rate-limited to ≥ 2 s, with a 60 s
  fast-cadence window), and correctness never depends on it.

### ChaCha20-Poly1305: libcrypto when it is there (measured on this machine)

Every poll seals a request and opens the response, from an otherwise idle loop, so
`lib/omclip/crypto.py` takes ChaCha20-Poly1305 from the system OpenSSL — `libcrypto`,
located with `ctypes.util.find_library("crypto")` — through `ctypes`
(`EVP_chacha20_poly1305`: 12-byte nonce, 16-byte tag appended to the ciphertext, AAD fed
through the update call with a NULL output buffer). No third-party package, nothing
compiled into the repo, and **the wire bytes do not change**: the RFC 8439 vector and
randomized inputs are compared against the pure-python implementation, in both directions,
by the test suite.

* `OMCLIP_CRYPTO=python` forces the pure-python implementation. That is also how the
  suite covers it: `tests/test_crypto.py` runs itself a second time in a child interpreter
  with the variable set, so the whole crypto module passes with libcrypto out of the picture.
* Any failure falls back to the pure-python code and the daemon never errors: no libcrypto
  at all, no `EVP_chacha20_poly1305` symbol, a load error, a call error. Silent on the wire,
  but not unobservable — `health.crypto_backend` (`libcrypto` · `python`) and
  `health.crypto_detail` (the reason, null while healthy) are in `omclip status --json`, in
  the `crypto` field of the human status line, and as `omclip doctor`'s `crypto-aead` line
  (`OK` for libcrypto, `WARN` carrying the reason for the fallback: a fallback is ~80× the
  CPU per poll, not a failure). Internally that is `crypto.aead_backend()` /
  `crypto.aead_detail()`. Shapes libcrypto cannot take — key ≠ 32 bytes, nonce ≠ 12 bytes,
  a blob shorter than a tag, `bytearray` input — go down the pure-python path and fail
  exactly as they used to, so a malformed argument can never make OpenSSL over-read.
* Measured here (Python 3.14.7, OpenSSL 3.6.4 = `libcrypto.so.3`), one encrypt + one
  decrypt through the public API, `time.perf_counter`, 2000 iterations at 412 B / 100 at
  64 KiB for pure python, 20000 at both sizes for libcrypto:

  | payload | pure python | libcrypto | speedup |
  |---|---|---|---|
  | 412 B request (frame-header AAD) | 3326 µs/op (6.65 s / 2000) | 42.6 µs/op (0.85 s / 20000) | 78× |
  | 412 B request (no AAD) | 3303 µs/op (6.61 s / 2000) | 37.1 µs/op (0.74 s / 20000) | 89× |
  | 64 KiB payload | 424 824 µs/op (42.48 s / 100) | 190 µs/op (3.81 s / 20000) | 2231× |

  (The first call in a process costs extra once: ~0.7 ms for libcrypto — OpenSSL's provider
  fetch — and ~3.4 ms for pure python. A 64 KiB item in pure python is 425 ms of CPU per
  seal, which is the stronger argument for this change than the poll loop: `max_bytes` is
  256 MiB.)
* At the daemon's cadence — one sealed request + response per peer per 2 s poll
  (`poll_seconds=2.0`), 412 bytes — an answering peer costs **0.166 % of one core in pure
  python, 0.002 % with libcrypto** (two answering peers: 0.333 % → 0.004 %). Session setup
  (pair-verify is a few more AEAD ops) and the 20 s idle cadence are the small remainder.
* For scale, the same daemon measured **1.03 % and 1.07 % of one core** over 30 s and 60 s
  (`/proc/<pid>/stat` utime+stime) with the Mac answering every 2 s and the iPhone out of
  AWDL range. The earlier note that the whole "~1.5 % is pure-Python ChaCha20" was too
  strong: AEAD was the largest cryptographic item but only ~0.17 of that ~1 point with one
  peer answering, ~0.33 with two. What this change removes is that share (78×); the rest of
  the daemon's cost is the poll machinery — discovery, connect/`select`, `status.json` at
  1 Hz — and is untouched.

### Discovery

* **Mac (LAN)**: a vendored stdlib mDNS resolver
  queries `_companion-link._tcp.local` over IPv4 *and* IPv6 multicast on the LAN interface;
  `avahi-browse -rtp _companion-link._tcp` is a fallback. The byte layout is the reason the
  resolver is vendored rather than shelling out to avahi everywhere: **avahi is configured to
  deny `awdl0`** (`deny-interfaces=awdl0,…`) and `avahi-browse` needs the service name
  *without* the `.local` domain — passing `.local` silently matches nothing.
  Several devices answer `_companion-link` on a home LAN (this one has an Apple TV and Hue
  bridges), so an mDNS instance is only trusted when it reports the address we are configured
  to talk to (`mac_host`); otherwise the configured `mac_host`+`mac_port` are used, which is
  the path that worked here (own resolver and avahi both agree on the Mac at
  `<mac-host>:49152`).
* **iPhone (AWDL)**: the peers omdrop's AWDL daemon hears *now*
  (`/run/awdl-discoverable/peers.json`, MAC → EUI-64 link-local, strongest signal first;
  `ip -6 neigh show dev awdl0` only when that table is missing), then **unicast** mDNS SRV
  queries to all of them at once from one socket — silent peers are asked a second time
  after 1.5 s, because the iPhone ignored a first query and answered the repeat — for its
  **ephemeral** port. The address that last resolved is tried first and kept across restarts
  in `~/.local/state/omclip/phone.json`; AWDL addresses that turned out to be the Mac are
  skipped. Re-resolved on every reconnect (iOS mints a new
  port per service start). Multicast does not work on `awdl0` here, which is exactly why the
  unicast path exists. No `awdl0` → the phone is `unreachable` with a detail naming
  `omdrop on`; an address but no `_companion-link` answer → `locked` with "iPhone must be
  unlocked" (a locked iPhone answers nothing at all).

### Bulk transfer: how it works (2026-10-14)

A pasteboard over ~10 KB does not arrive in the `com.apple.handoff.payload-request`
response. That response carries a 324-byte `extraData` descriptor
(`{author_data{unique_id, manager_id, client_id}, bonjour_name, message_version: 1}`) and a
type table whose `DataSize` is larger than those bytes, and the payload is served over a
TLS connection `sharingd` publishes as a `_continuity._tcp` instance (port 8771).
`omclip` now fetches it. The wire format, confirmed against this Mac (macOS 27, five
fetches, byte-identical payloads) and implemented in `lib/omclip/bulk.py`:

* `bonjour_name` names the sender's instance (`97b1f7346d19` at `<mac-host>:8771`); the
  iPhone advertises its own on the LAN (`59b7e9bcc17f`). The endpoint is TLS 1.2 with an
  Apple ID certificate, requests a client certificate, and completes the handshake with
  omdrop's identity (`~/.omdrop/keys`) — the same Apple ID requirement as AirDrop.
* The first message is `0x01 | BE32 length` followed by an **NSKeyedArchiver** archive of
  `{StreamMessageType: 0, StreamMessageVersion: 1, RequestAuthorData: …}`. The crux:
  `RequestAuthorData` must be the **author-data blob** (`extraData.author_data`, the nested
  property list `+[SFCompanionService serviceFromAuthorData:]` parses). Sending the parsed
  dictionary instead gets *no answer at all* — the connection is accepted and left open.
* The reply is the same framing with `CompanionStreamConnectResponse`; from there the pipe
  is no longer a message protocol. The holder runs **coder V2** (`UCStreamCoderV2`), not
  V1: `'C' 0x01 tag:BE32 len:BE32`, bodies packed as `MP\x03\x05` + MessagePack.
* The receiver drives it: tag 3 → tag 4 (`{"data": <archive of the type table>}`), tag 5 →
  tag 6 (64 KiB chunks that concatenate to exactly `DataSize`), and tag 7
  (`{"supportsCompression": false, "uuid": <the item's NSUUID, upper case>}`) → tag 8,
  whose chunks are an **AppleArchive** (`AA01`) holding the file's bytes. A record is
  `AA01`, a **two-byte header length**, then the fields (`TYP`, `PAT`, `SIZ`/`DAT`,
  `XAT`/`ACL`, `CKS`, `SH1`/`SH2`, …), and the file's data begins where that header length
  says it does — `archive[at + header : at + header + DAT]`. Everything the entry carries
  that is not a field (the xattr/ACL **blob pool**) is written *after* the data, so the
  last `DAT` bytes of the archive are the data *plus* the pool shifted into it: a landed
  file of exactly the declared size that is still not the file. Read the header, never the
  archive's end. A file copy's *body* is therefore never in the payload: the payload
  carries the `file://` URL, the name and a 308 KB Finder icon (`com.apple.icns`, which is
  what makes a Finder copy bulk), and the body follows as that separate archive (measured:
  `totalSize` 2 309 236 = 308 686 payload + 2 000 550 archive).

What the daemon does with a bulk generation:

* fetch it once, slice the fetched flat buffer with the item type table (never the
  descriptor), and mirror the best representation through the same decision path as an
  inline generation — so a large text pasteboard mirrors as text and an image as its bytes;
* stream a file body to `download_dir` (`~/Downloads`, settable), honouring `max_bytes` as
  the cap: a file past the cap is **refused, never truncated**, and an existing name is
  never overwritten (`name (1).ext`). A landed file is offered as `text/uri-list` pointing
  at it, so pasting gives the local file rather than the sender's path;
* say where it went: the fetch line names every landed file —
  `bulk payload fetched peer=mac bytes=312874 files=1
  landed=/home/user/Downloads/IMG_1739.HEIC (1631561 B) endpoint=<mac-host>:8771` — one
  line per fetch, never the sender's path and never the file's bytes. The `mirrored` line
  repeats that path, and `clipboard.last_file` in `status.json` carries the name, the
  absolute path and the size, which is what `omclip status` and the panel show. The
  `file://` URI the clipboard actually holds is 48 bytes for that copy and is never
  reported as the size of the file;
* keep the descriptor as evidence in `~/.local/state/omclip/bulk/` (newest 10).

Generation suppression: the identity of a pasteboard is its **item UUIDs + `DataSize`**, not
the descriptor's `unique_id` — the Mac re-mints `unique_id` on *every* response (measured
2026-10-14: eight announcements 3 s apart, eight different ids, byte-identical item tables),
so an identity built on it could never suppress anything. A pasteboard is attempted **once**;
the polls after an attempt are `unchanged`. A generation whose fetch *failed* is retried at
most every 30 s (so a transient failure — the Mac asleep, mDNS busy — still recovers), and a
*refused* one (too large, or a layout we do not decode) is not retried at all:
`clipboard.skipped.bulk` counts attempts that did not mirror, `oversize` counts what
`max_bytes` refused. Because the item UUIDs persist while the pasteboard holds the same items,
re-copying the same file does not produce a new identity and is not fetched again.

Honest limits, none of them exercised by a passing test against the real peer:

* **Coder V2 only.** V1 (`"==="` push framing) is detected, named in the log and refused —
  the holder picks the coder (`sendingCoderVersion`) and no build here has ever selected V1.
* **Suppression trusts the item table.** Two pasteboards with identical UTI/offset/size/UUID
  tables and identical `DataSize` are the same identity, so a *different* copy that reuses
  every item UUID (which is what re-copying the same file does) is deliberately not
  re-fetched. A changed copy whose item UUIDs also change is fetched normally.
* **AppleArchive decoding is single-file.** The decoder reads one file entry, stored or one
  raw-deflate stream. The entry's data is located by the record's own header length
  (`at + header`, the `u16` after `AA01`) — *not* by the archive's total size: the xattr/ACL
  blob pool follows the data, so `total - DAT` starts `len(pool)` bytes into the file and
  appends the pool, landing a file of exactly the declared size that is still wrong (this is
  what happened to the first HEIC copies: 1 631 561 B and 2 843 090 B — the latter exactly
  the Mac's size — of shifted content, so **a size check is not an integrity check**). The
  decoded bytes are now also checked against the record's `SH1`/`SH2` (SHA-1/SHA-256 of the
  data) and a mismatch, an out-of-bounds region or a header that does not end where it says
  it does is a **refusal**, with the file deleted, rather than a plausible-looking landing.
  A multi-file archive, or any framing this decoder does not recognise, is refused with its
  observed sizes and nothing is written.
* **The iPhone path is unverified.** The AWDL variant resolves the peer's instance with a
  unicast query and binds to `awdl0` (as `tools/bulk_probe.py` does), but no iPhone bulk
  generation has been observed from here.
* `tools/bulk_probe.py` remains the read-only research tool: it checks the newest evidence
  file against the advertised services and performs the mutual-TLS handshake without
  fetching anything.

## Privacy

* `omclip` holds this device's own account identity and speaks for it — nothing is extracted
  from the Mac or the iPhone keychain, and Universal Clipboard is never routed through another
  Apple device.
* Credential material is **read in place** (`identity_dir`, `keys_dir`) and never copied into
  this repo, its git history, or any state file:
  `git ls-files | grep -Ei '\.(pem|cms|key)|rapport_'` is empty.
* **Clipboard contents are never logged.** The log carries digest prefixes, sizes, UTI names
  and error text only. A ≤160-character text preview (text UTIs only, `preview = true`) is
  written to `~/.local/state/omclip/status.json` for the panel and never to the log.
* A file body fetched over the bulk transfer is written to `download_dir`
  (`~/Downloads` by default, `omclip config set download_dir …`) by design — it is the file
  the user copied — and the log names that path and the file's size, which is why the path
  contains the file's name. `status.json`'s `clipboard.last_file` publishes the same three
  facts (name, absolute local path, size) to the panel, so nothing has to guess the file
  from the 48-byte `file://` URI that is actually on the clipboard. Nothing else about the
  file is logged, and the *sender's* path never is.
* No network access beyond the LAN/AWDL peer connections to the Apple devices you point it
  at; no telemetry, no uploads.
* `omclip` starts `bluetooth.service` and powers the adapter only while it mirrors the iPhone
  (the BLE wake advertisement an asleep iPhone needs), records that as
  `health.bluetooth_owned: true`, and releases exactly that — stop the unit, re-block rfkill —
  on `omclip off`. A `bluetooth.service` that was already running is left alone, and `omclip`
  never repairs a wedged controller (see *Troubleshooting*). `omdrop on` is run only as the
  window `omclip` opens itself for the phone scope.

## Troubleshooting

**`state: degraded` with a connection error.** Read `omclip status --json` → `peers[].detail`
and `omclip log`. The Mac may simply be off/out of reach: `address`/`port` show what was
tried, and reconnects back off up to 30 s. A TCP-level check is
`cat < /dev/null > /dev/tcp/<mac-host>/49152`.

**Bluetooth controller wedged.** Symptom seen here: `bluetoothctl power on` →
`org.bluez.Error.Failed`, bluetoothd logging `Adv Monitor Manager … supported
features:0x00000000`, then both the monitor and discovery backends are dead.
`omclip doctor`/`status` report `bluetooth: "wedged"` when the adapter says "powered off"
while `bluetoothd` runs, or when `btmgmt info` reports no supported settings. `omclip` only
detects and reports this — it never repairs. Clearing it has needed a `btusb` reload or a
reboot here; the kernel-side state is visible with `btmgmt info` / `bluetoothctl show`. After
any bluetoothd restart, the AWDL advertiser must be re-registered: `omdrop off; omdrop on …`.

**A bulk pasteboard did not mirror.** The daemon fetches it over the companion stream and
says what happened: `peer pasteboard is bulk mode; not mirrored … detail=<why>` (one line per
generation, `detail` carrying the wire error, the refusal or `bulk generation already
attempted`), `clipboard.skipped.bulk` counting attempts that did not mirror and
`peers[].last_generation` keeping `reason`/`bytes`/`mirrored` (with `bulk: true` for a
generation whose bytes were fetched). Usual causes: the Mac's pasteboard has moved on (a
descriptor is only good while the sender still holds that copy), the copy is larger than
`max_bytes` (`oversize`), or the holder answered with V1 `===` framing, which this build
never uses and does not implement. Copying from a plain-text source (Notes, Messages, a
terminal) stays under the threshold and arrives inline; a rich or large copy goes through
the stream. A fetched *file* lands in `download_dir` (`~/Downloads` by default), with
`name (1).ext` when that name is taken, and the log's fetch line names its path and its
size; `omclip status` and the panel name it too, from `clipboard.last_file`.

**Credentials expiring or missing.** `omclip status --json` → `credentials[]` and `omclip
doctor`. Two different files expire on two different clocks, and `omclip` reports each from its
own source rather than reusing one date (measured on this machine, 2026-10-13):

| file | expiry source | measured |
|---|---|---|
| `certificate.pem` | `openssl x509 -enddate` (`notAfter`) | **2027-11-12** — a real Apple cert, ~13 months |
| `validation_record.cms` | its own CMS payload: `ValidAsOf + SuggestValidDuration` | **2026-11-12** — 30 days, so this is the one that goes stale first |

`status`/`warn` (`≤ 14 days`) / `expired` / `missing` / `unknown` apply per file, so the
panel's warning fires on whichever is closest — normally the record. A file that is present but
whose expiry cannot be parsed is `unknown`, never `ok`. Refresh them as described in
[Credentials](#credentials), then `omdrop off; omdrop on 10`. `omclip` reports, never fixes,
and never copies those files.

**The iPhone peer never becomes reachable.** It needs an AWDL window: `omclip on` opens
one via `omdrop on <duration>` (and closes it on `omclip off` only if it opened it). Check
`omclip status --json` → `peers[phone].detail`, `health.awdl`/`health.omdrop`/`omdrop_owned`, and
`ip -6 neigh show dev awdl0`. Measured behaviour on this machine (2026-10-13):

* `omclip on` brings the radio up before anything else needs it: `rfkill unblock bluetooth`,
  `systemctl start bluetooth.service` if it was inactive, then power on — that state is what
  lets `omdrop`'s advertiser wake a sleeping iPhone, and it is what `health.bluetooth: "ok"`
  reports. `bluetooth_owned: true` means `omclip` started it, so `omclip off` stops it again and
  re-blocks rfkill, returning this machine to its ~3.35 W idle. A service the user started is
  reported as `bluetooth: "ok"`, `bluetooth_owned: false`, and left running.
* With `bluetooth.service` inactive, `omdrop on` still brings `awdl0` up and the window is owned
  by `omclip` (`omdrop_owned: true`, `omdrop status --json` → `mode: "timed"`). `omclip off` then
  closes it again (`awdl0` down, omdrop `mode: "off"`).
* **If `omdrop on` fails from the daemon but works in your shell, check the unit's hardening.**
  `NoNewPrivileges=yes` in `omclip.service` makes it fail with `pkexec must be setuid root`
  (`omdrop` escalates through pkexec), so the unit deliberately does not set that flag. A failed
  start is one `warn` line, retried every 60 s, and its reason appears in the phone peer's
  `detail` — never a crash or a retry storm.
* The AWDL neighbour table keeps **stale static entries** (`PERMANENT`) for devices that are long
  gone — measured 31 rows with the iPhone 14th, while omclip asked only the first 4 — which is
  why candidates come from omdrop's live peer table instead.
* **The Mac answers `_companion-link` over AWDL too** — as `CLink-…` on a UUID host name at
  its fixed rapportd port, so the advertised name never says "Mac". `omclip` therefore refuses
  an AWDL discovery result that is the Mac (fixed port, host name, address, or the name the
  Mac reports on the LAN), and drops a phone session whose `_systemInfo` names the Mac, so the
  Mac can never be mirrored twice — once as `mac` and once as `phone`. `status` runs the same
  consolidation on its peer list as a last line of defence. If auto-detection is still
  ambiguous on your network, pin the phone: `omclip config set phone_address fe80::…`
  (the strongest live peer — `omclip status --json` shows the address it last used).
* `locked` means every neighbour answered nothing: an iPhone stops answering its `rapportd`
  entirely when locked, so "iPhone must be unlocked" is the actionable reading. It is
  re-checked on the `locked_poll_seconds` cadence (30 s by default), never in a tight loop.

**`omclip status` says `stale: true`.** The unit is active but the daemon has not written a
heartbeat for >10 s. That is what a hung or wedged daemon looks like: `omclip log -n 40`,
then `omclip off` / `omclip on`.

**Nothing mirrors even though `state: on`.** Check `peers[].last_generation.reason` and
`clipboard.skipped`: `unchanged` means the peer has no new generation (the common case),
`local_echo` means the item is already on the clipboard, `oversize` means it exceeded
`max_bytes`, `nodata` means the peer answered metadata only.

**The mirrored text is gone from the clipboard after `omclip off`.** Expected, and measured on
2026-10-13 (journal §7): the daemon mirrors with `wl-copy`, whose forked daemon owns the Wayland
selection, and that process lives in `omclip.service`'s cgroup. Stopping the unit kills it, the
selection has no owner left, and `wl-paste` prints `Nothing is copied` — it does not restore what
was on the clipboard before the mirror either. Leave `omclip on` if you want the mirrored copy to
stick, or copy again on the Apple device.

## Files

| path | what |
|---|---|
| `~/.config/omclip/settings` | configuration (validated on load) |
| `~/.local/state/omclip/status.json` | the status document the daemon writes at ≥ 1 Hz |
| `~/.local/state/omclip/omclip.log` | daemon log, rotated at 512 KB (1 generation) |
| `~/.local/state/omclip/{lock,desired.json,runtime.json}` | single-instance lock, `on` intent, owned AWDL window |
| `~/.config/systemd/user/omclip.service` | the user unit `omclip on` starts |
| `~/.local/bin/omclip` | symlink into this repo |
| `~/.config/omarchy/plugins/bxshi.omclip` | the Omarchy plugin (created by the plugin deliverable; it is a symlink to this directory) |

## Layout

| path | what |
|---|---|
| `bin/omclip` | single entry point (CLI + `daemon`) |
| `lib/omclip/crypto.py` | vendored protocol primitives (X25519, ChaCha20-Poly1305 — libcrypto via ctypes when available, pure-python otherwise — HKDF-SHA512, Ed25519, TLV8, OPACK) |
| `lib/omclip/protocol.py` | framing, content channel, Pair-Verify, `_systemInfo`, payload requests |
| `lib/omclip/session.py` | the hardened one-session-per-peer request loop |
| `lib/omclip/pasteboard.py` | `UASharedPasteboardInfoWrapper` decoding + the mirror/skip decision |
| `lib/omclip/clipboard.py` | `wl-copy`/`wl-paste`, echo state |
| `lib/omclip/discovery.py` | vendored mDNS resolver, AWDL neighbours, avahi fallback |
| `lib/omclip/ble.py` | Handoff `0x0c` TLV handling + the guarded Advertisement Monitor |
| `lib/omclip/{bluetooth,omdrop,credentials,identity}.py` | health/expiry/ownership probes (detect only) |
| `lib/omclip/{settings,duration,backoff,peer,state,status,log}.py` | configuration, windows, backoff, the status document |
| `lib/omclip/daemon.py`, `lib/omclip/cli.py` | the daemon and the frozen CLI contract |
| `share/omclip.service`, `install.sh`, `uninstall.sh` | packaging |
| `tests/` | offline `unittest` suite (`python3 -m unittest discover -s tests -v`) |
| `docs/status-schema.md` | schema 1, field by field, with a real sample |
| `ACKNOWLEDGEMENTS.md` | upstream research and open-source acknowledgements |

## Hardware Limitation & Platform Notes

> **Hardware Limitation Notice**: This software and protocol testing has been developed and tested on an older Intel MacBook Air (MacBookAir6,2 / Core i5-4250U) running Linux without a T2/Secure Enclave security chip.

* Apple Continuity pairing/pairing-verify and Rapport crypto work standardly via RSA/Curve25519/AES-GCM in software.
* However, hardware-dependent hooks like Secure Enclave keychain extraction or T2-specific AWDL quirks differ from modern Apple Silicon (M1/M2/M3/M4) or T2-equipped Macs. On devices with Secure Enclave hardware, keys may not be extractable via standard software keychain utilities without specialized tooling or alternate authentication paths.

## Disclaimer

`omclip` is an independent, unofficial project based on protocol reverse-engineering for
interoperability with devices you own. It is not affiliated with, endorsed by, or supported by
Apple Inc. Apple, Mac, iPhone, AirDrop, Handoff and Universal Clipboard are trademarks of Apple
Inc. Use it only with your own devices and accounts; it may break with any OS update.

## Acknowledgements

`omclip` stands on the shoulders of the open-source community and security researchers who reverse-engineered Apple's proprietary protocols:

* **[pyatv](https://github.com/postlund/pyatv)** (Pierre Ståhl & contributors): The OPACK and TLV8 serialization and MRP protocol foundations that made clean Python-native Apple protocol implementations possible.
* **[OpenDrop / OWL (Open Wireless Link)](https://github.com/seemoo-lab/opendrop)** (Secure Mobile Networking Lab, TU Darmstadt): Groundbreaking work on reverse-engineering Apple Wireless Direct Link (AWDL), AirDrop framing, and companion protocol interactions.
* **[airdrop-keychain-extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor)** (Secure Mobile Networking Lab, TU Darmstadt; GPL-3.0): The keychain-extraction approach (SIP/AMFI relaxation and the `keychain-access-groups` entitlement) for obtaining your own AirDrop Apple-ID identity. `omclip` does not bundle it.
* **Apple Continuity & Handoff reverse-engineering community**: Researchers and projects detailing the Rapport daemon, Companion Link, `_continuity._tcp`, and Pair-Verify protocols.
* **OpenSSL / libcrypto**: High-performance ChaCha20-Poly1305 and cryptographic operations.
