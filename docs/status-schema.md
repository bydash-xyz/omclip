# `omclip status --json` — schema 1 (frozen contract v1)

Everything the plugin renders comes from this document. `omclip status --json`,
`omclip peers --json` (the same peer objects) and the `status.json` the daemon writes at
≥ 1 Hz all follow it. Extra keys are only ever **added** — v1 field names are never renamed
or reused, and the additions in this build (`health.ble_backend`/`health.ble_detail`,
`health.crypto_backend`/`health.crypto_detail`, `health.bluetooth_owned`,
`credentials[].detail`, `clipboard.last_file`) are documented below.

Invariants the plugin can rely on:

* One JSON object on stdout, exit 0 — even when the daemon is stopped, missing or stale.
  `state: "off"` with every peer `disabled` is the honest no-daemon answer, not an error.
* `status` never opens a peer connection and never blocks on the network: measured 0.38-0.44 s
  on this machine (budget: < 3 s). Health and credential expiry are probed live on every call,
  so they stay truthful when the daemon is dead.
* `peers` always contains both peers, in the order `mac`, `phone`; one that is out of scope (or
  any peer while the daemon is off) is `disabled`. Both are in scope for every `omclip on`:
  there is no scope switch. The same physical device never appears twice — the Mac identifying
  itself on AWDL is dropped from the `phone` peer rather than mirrored under both keys, and its
  address is never shown as the phone's.
* Peer states are exactly:
  `disabled` (not in scope / daemon off) · `resolving` (mDNS/neighbour lookup) ·
  `connecting` (TCP + Pair-Verify) · `authenticated` (session up, nothing polled yet) ·
  `polling` (a payload request is in flight) · `idle` (session up, waiting for the next poll) ·
  `locked` (the iPhone answered nothing, which is what a locked phone does) ·
  `unreachable` (no address to try: AWDL down, no neighbour) ·
  `error` (last attempt failed; `detail`/`last_error` carry the reason).
* Nothing in here ever contains clipboard contents beyond `clipboard.last_preview`, which is a
  ≤ 160-character, text-UTI-only preview and is never written to the log, and
  `clipboard.last_file`, which names a file omclip itself wrote under `download_dir` — a path
  is not the file's bytes, and the *sender's* path is never published.

## Fields

### Top level

| field | type | meaning |
|---|---|---|
| `schema` | int | `1`. Bump only for a breaking change. |
| `version` | str | `omclip` version that produced the document (this build: `0.1.0`). |
| `state` | str | `off` · `starting` · `on` · `degraded` · `error`. See below. |
| `on` | bool | True while the daemon is running (or starting). `false` whenever `state == "off"`. |
| `since` | int\|null | Epoch seconds the current window started; null when off. |
| `expires_at` | int\|null | Epoch seconds the window ends; null = `forever` (or off). |
| `seconds_left` | int\|null | Recomputed live from `expires_at` on every call; null = forever/off. |
| `scope` | list[str] | The peers being mirrored. Always `["mac","phone"]` for a daemon started by `omclip on`; the historical `["mac"]`/`["phone"]` values can only come from an old `desired.json`. |
| `duration` | str | The window as requested: `forever`, `once`, `30s`, `10m`, `1h`, `90m`. |
| `stale` | bool | True when the unit is active but the daemon's heartbeat is older than 10 s (hung/wedged daemon). A stale document still reports the daemon's last state — read this flag before trusting the rest. |
| `instance` | obj | The daemon process. |
| `peers` | list[obj] | Always `mac`, `phone`. |
| `clipboard` | obj | Mirror rollup. |
| `health` | obj | Radio/clipboard facts, probed live. |
| `credentials` | list[obj] | AirDrop + Rapport identity files. |
| `errors` | list[str] | Fatal problems plus, while `degraded`, one line per in-scope peer. Empty is the normal case. |

**`state` in practice**

| value | when |
|---|---|
| `off` | the unit is not active (or the daemon never started writing). Peers are `disabled`; health and credentials are still live. |
| `starting` | the unit is active but no full poll round has completed yet (or the daemon has not written its first document). |
| `on` | at least one in-scope peer has a live session (`authenticated`/`polling`/`idle`). A peer that is broken while another works is still `on` — its reason is in `peers[].detail`. |
| `degraded` | the daemon is up but **no** in-scope peer is reachable; `errors` lists why. |
| `error` | fatal: the identity (`identity_dir`) is unreadable/absent, so `omclip` cannot authenticate at all. Nothing cheerful is reported. |

### `instance`

| field | type | meaning |
|---|---|---|
| `pid` | int\|null | MainPID (from the unit, or from the daemon's own document). |
| `rss_kb` | int\|null | Resident set size in kB, read from `/proc/<pid>/status`. |
| `uptime_s` | int\|null | Seconds since the daemon started. |
| `unit` | str | Always `omclip.service`. |
| `unit_state` | str | systemd's view: `active`, `inactive`, `failed`, `activating`, … |

### `peers[]`

| field | type | meaning |
|---|---|---|
| `key` | str | Stable identity: `mac` \| `phone`. Never changes. |
| `kind` | str | `mac` \| `iphone` \| `unknown` (currently always the first two). |
| `label` | str | What to show the user. Defaults to `MacBook Pro`/`iPhone` and is upgraded to the peer's own name once we learn it (mDNS instance name, or the `name` in its `_systemInfo` reply). |
| `transport` | str | `lan` (the Mac's own `rapportd`) \| `awdl` (the iPhone). |
| `address` / `port` | str\|null / int\|null | The pair being dialled, or — while a lookup cannot resolve — the last pair actually resolved for that peer (for the phone: the remembered AWDL address with the port that came with it). The two always belong to the same device; an AWDL neighbour that was only asked, or one that is the Mac, is never published as the phone's address. For the phone this is re-resolved every reconnect (iOS mints an ephemeral port). |
| `state` | str | See the invariant list above. |
| `detail` | str\|null | One human sentence when the state needs explaining, e.g. `iPhone must be unlocked`, `awdl0 is down: …`, or the last connect error. |
| `last_seen` | int\|null | Epoch seconds of the last completed exchange. |
| `last_error` | str\|null | Message of the last failure; cleared on success. |
| `attempts` | int | **Consecutive failed attempts** (0 = healthy). Drives the backoff 1/2/4/8/16/30 s ±20 %. |
| `last_generation` | obj | The last pasteboard generation seen from this peer (see below). |

`last_generation`:

| field | type | meaning |
|---|---|---|
| `digest` | str\|null | `sha256(uti + b"\x00" + representation bytes)`, hex. null for bulk/empty/nodata generations, which have no representation. |
| `at` | int\|null | Epoch seconds of the last generation *decision* for this peer. |
| `uti` | str\|null | UTI of the representation that was considered (or would have been). |
| `bytes` | int\|null | Size considered: the representation's length, or the deferred `DataSize` (312 874 for the pasteboard generation this was measured on — that is the pasteboard payload, **not** the file). A generation whose file landed and mirrored reports the landed file's own size instead, so a file copy never reads as "48 bytes"; the file's name and path are in `clipboard.last_file`. |
| `mirrored` | bool | True only if this generation was actually copied to the Wayland clipboard. A failed `wl-copy` leaves `false` (and sets `last_error`). |
| `reason` | str\|null | `mirror`, `unchanged`, `bulk`, `empty`, `local_echo`, `oversize`, `nodata`. A deferred generation that was fetched reports `mirror` (or `unchanged`/`oversize` afterwards); `bulk` is the one that could not be fetched. |
| `bulk` | bool | True when the peer deferred the bytes (`DataSize > len(extraData)`). The 324-byte descriptor is never sliced as payload — `bulk.py` fetches the flat buffer the type table indexes. |

### `clipboard`

| field | type | meaning |
|---|---|---|
| `mirrored_total` | int | Items actually put on the clipboard since the daemon started. |
| `last_mirrored_at` | int\|null | Epoch seconds of the last successful mirror. |
| `last_digest` / `last_uti` | str\|null | What that item was: the digest of the mirrored representation and its UTI. Never content. A file copy is `public.file-url` — the offer on the clipboard is a `text/uri-list` of one `file://` URI. |
| `last_bytes` | int\|null | The size of what the user received. For a file mirror that is the **landed file's own size**, never the byte count of the `file://` URI that is actually on the clipboard (48 for the 1 631 561-byte HEIC copy this was measured on: the URI is `file:///home/user/Downloads/omclip/IMG_1739.HEIC`); otherwise the mirrored representation's length. `last_file.bytes` carries the same number for a file. |
| `last_file` | obj\|null | **Addition to v1.** The file a file-copy mirror landed: `{"name": "IMG_1739.HEIC", "path": "/home/user/Downloads/IMG_1739.HEIC", "bytes": 1631561}` — the name the sender's archive carried, where it was written (`download_dir`, absolute) and its size. `null` for every non-file mirror and while nothing has been mirrored. The path is omclip's own (`download_dir`, never the sender's), and its name is not clipboard content. |
| `last_preview` | str\|null | ≤ 160-character preview, **text UTIs only**, and only while `preview = true`. Never logged; lives only in this document. `null` for a file mirror (there is no text representation to preview) — that is the row `last_file` fills. |
| `skipped` | obj[int] | Counters for `unchanged`, `bulk`, `empty`, `local_echo`, `oversize`, `nodata`. |

**Reading the counters.** They increment once per poll-round decision, so with a healthy peer
whose clipboard has not changed, `unchanged` climbs at the poll cadence — that is the expected
shape of a working idle mirror, not churn: the *log* says it once per new generation, and the
clipboard is not touched. `bulk` is the exception: a deferred item is *attempted* once per
generation and its repeats are `unchanged`, so `bulk` counts the attempts that did not mirror
(a failed one is retried at most every 30 s, a refused one not at all). `mirrored_total` is the
counter that only moves on real work.

### `health`

| field | type | meaning |
|---|---|---|
| `bluetooth` | str | `ok` · `off` · `wedged` · `unknown`. |
| `bluetooth_detail` | str\|null | Why: inactive/disabled `bluetooth.service`, soft-blocked (rfkill), adapter powered off while bluetoothd runs, or no supported settings (`features 0x00000000`). |
| `awdl` | str | `up` · `down` · `unknown` (`down` also means "no `awdl0` at all", which is the normal state without an `omdrop` window). |
| `omdrop` | str | `on` · `off` · `unknown` — read from `omdrop status --json`, never from human output. |
| `omdrop_owned` | bool | True only while the AWDL window open right now was opened by `omclip` (so `omclip off` may close it). |
| `bluetooth_owned` | bool | **Addition to v1.** True while the `bluetooth.service` running now was started by `omclip` (with the adapter unblocked and powered) for the phone's BLE wake advertisement, so `omclip off` may stop it and re-block rfkill. False when the service was already running: omclip then leaves it alone. |
| `wl_clipboard` | bool | `wl-copy` and `wl-paste` resolve. |
| `wayland` | bool | `WAYLAND_DISPLAY` resolves to a socket in `XDG_RUNTIME_DIR`. |
| `ble_backend` | str | **Addition to v1.** `monitor` (BlueZ Advertisement Monitor registered) · `unavailable` (bindings missing, bluetooth not `ok`, registration failed, or `ble_trigger = false`) · `unknown` (daemon off). |
| `ble_detail` | str\|null | **Addition to v1.** The one-sentence reason the BLE trigger is not in use; `omclip` logs it once and polls on the timer instead. |
| `crypto_backend` | str | **Addition to v1.** Which ChaCha20-Poly1305 the daemon's own process loaded: `libcrypto` (the system OpenSSL's `EVP_chacha20_poly1305` through `ctypes` — the wire bytes are checked against the pure-python code) · `python` (the vendored pure-python AEAD: correct, but ~80× the CPU on a 412-byte request+response and ~2230× on a 64 KiB item) · `unknown` (daemon off). |
| `crypto_detail` | str\|null | **Addition to v1.** The one-sentence reason the pure-python implementation is in use — no libcrypto, no `EVP_chacha20_poly1305` symbol, a load or call-time failure, or `OMCLIP_CRYPTO=python` (echoed as it was set). null while libcrypto is live. `omclip doctor` reports the pair as `OK`/`WARN` (`crypto-aead`): a fallback is slow, not broken. |

### `credentials[]`

| field | type | meaning |
|---|---|---|
| `file` | str | Path, `~`-abbreviated. Read in place; never copied into the repo. |
| `kind` | str | `airdrop-certificate` · `airdrop-key` · `airdrop-validation-record` · `rapport-identity` · `rapport-ids`. A file that is present but whose expiry cannot be read is `unknown`, never `ok`. |
| `not_after` | str\|null | ISO-8601 UTC. For `airdrop-certificate` it is `openssl x509 -enddate`; for `airdrop-validation-record` it is the record's own clock, `ValidAsOf + SuggestValidDuration` read from the CMS payload (`openssl cms -verify -noverify`). **The two are different dates** — measured here: certificate `2027-11-12`, record `2026-11-12` — and the record is the one that usually expires first. null for files with no parseable expiry. |
| `days_left` | int\|null | Whole days until that file's own `not_after`; negative when past. |
| `status` | str | `ok` · `warn` (≤ 14 days) · `expired` · `missing` · `unknown` (present but unreadable). |
| `detail` | str\|null | **Addition to v1.** e.g. the pointer at `run_on_macos.sh`/`install_credentials.sh` when something is missing. |

### `status.json` extras (daemon-internal, not in `status --json`)

The file the daemon writes carries everything above plus `heartbeat` (epoch seconds, the field
`stale` is computed from), `pid`, `started_at`, `bluetooth_owned`, `omdrop_owned`, `ble_backend`,
`ble_detail`, `crypto_backend` and `crypto_detail`, so a direct reader of the file has the same
information. The CLI output is exactly the schema above — no heartbeat key — so the plugin can
validate strictly.

## Sample document

Real output of `omclip status --json` on this machine (2026-10-13, daemon on, the Mac peer
live on the LAN and the iPhone resolved over AWDL on its ephemeral port — the two devices
listed once each; the `health.crypto_backend`/`crypto_detail` pair below was added
2026-10-14 and reads `libcrypto` here):

<!-- SAMPLE:START -->
```json
{
  "schema": 1,
  "version": "0.1.0",
  "state": "on",
  "on": true,
  "since": 1791934220,
  "expires_at": null,
  "seconds_left": null,
  "scope": [
    "mac",
    "phone"
  ],
  "duration": "forever",
  "stale": false,
  "instance": {
    "pid": 151466,
    "rss_kb": 23740,
    "uptime_s": 156,
    "unit": "omclip.service",
    "unit_state": "active"
  },
  "peers": [
    {
      "key": "mac",
      "kind": "mac",
      "label": "User\u2019s Mac",
      "transport": "lan",
      "address": "10.0.0.2",
      "port": 49152,
      "state": "idle",
      "detail": null,
      "last_seen": 1791934358,
      "last_error": null,
      "attempts": 0,
      "last_generation": {
        "digest": null,
        "at": 1791934358,
        "uti": null,
        "bytes": null,
        "mirrored": false,
        "reason": "empty",
        "bulk": false
      }
    },
    {
      "key": "phone",
      "kind": "iphone",
      "label": "CLink-e0840eb7a1aa",
      "transport": "awdl",
      "address": "fe80::6c5f:a3ff:fe96:4a3f",
      "port": 55289,
      "state": "error",
      "detail": "timed out",
      "last_seen": null,
      "last_error": "timed out",
      "attempts": 1,
      "last_generation": {
        "digest": null,
        "at": null,
        "uti": null,
        "bytes": null,
        "mirrored": false,
        "reason": null,
        "bulk": false
      }
    }
  ],
  "clipboard": {
    "mirrored_total": 0,
    "last_mirrored_at": null,
    "last_digest": null,
    "last_uti": null,
    "last_bytes": null,
    "last_file": null,
    "last_preview": null,
    "skipped": {
      "unchanged": 0,
      "bulk": 0,
      "empty": 50,
      "local_echo": 0,
      "oversize": 0,
      "nodata": 0
    }
  },
  "health": {
    "bluetooth": "ok",
    "bluetooth_detail": null,
    "awdl": "up",
    "omdrop": "on",
    "omdrop_owned": true,
    "wl_clipboard": true,
    "wayland": true,
    "ble_backend": "unavailable",
    "ble_detail": "bluetooth off: bluetooth.service is inactive (normally disabled on this machine): the BLE trigger is unavailable; polling still works",
    "crypto_backend": "libcrypto",
    "crypto_detail": null
  },
  "credentials": [
    {
      "file": "~/.omdrop/keys/certificate.pem",
      "kind": "airdrop-certificate",
      "not_after": "2027-11-12T01:52:55Z",
      "days_left": 394,
      "status": "ok",
      "detail": null
    },
    {
      "file": "~/.omdrop/keys/key.pem",
      "kind": "airdrop-key",
      "not_after": null,
      "days_left": null,
      "status": "ok",
      "detail": null
    },
    {
      "file": "~/.omdrop/keys/validation_record.cms",
      "kind": "airdrop-validation-record",
      "not_after": "2026-11-12T02:04:37Z",
      "days_left": 29,
      "status": "ok",
      "detail": null
    },
    {
      "file": "~/.config/omclip/identity/rapport_identity.json",
      "kind": "rapport-identity",
      "not_after": null,
      "days_left": null,
      "status": "ok",
      "detail": null
    },
    {
      "file": "~/.config/omclip/identity/rapport_ids.json",
      "kind": "rapport-ids",
      "not_after": null,
      "days_left": null,
      "status": "ok",
      "detail": null
    }
  ],
  "errors": []
}
```
<!-- SAMPLE:END -->

## Validation

`omclip.status.validate(doc)` returns a list of schema violations (empty list = conforms) and
is exercised by `tests/test_status.py` for the off, starting, on/stale and degraded shapes, so
a field rename or a wrong type fails the offline suite instead of the panel.
