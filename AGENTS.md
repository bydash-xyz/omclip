# omclip — agent index & architecture

**Purpose.** Direct Apple Universal Clipboard mirroring for Omarchy (Mac over LAN, iPhone over AWDL), without Tether, Apple relay, or companion apps.

**Files.**
| path | role |
|---|---|
| `bin/omclip` | CLI entry point |
| `lib/omclip/` | Core implementation (daemon, cli, protocol, crypto, bulk, discovery, state, etc.) |
| `tests/` | Unit and end-to-end test suite (`python3 -m unittest discover -s tests`) |
| `share/omclip.service` | Systemd user unit template |
| `BarWidget.qml`, `Panel.qml`, `manifest.json` | Omarchy bar pill and panel plugin files |
| `install.sh`, `uninstall.sh` | Installation and removal scripts |

**Architecture notes.**
- One session per peer; bounded requests; generation tracking; echo suppression; adaptive polling.
- Uses system OpenSSL `libcrypto` via `ctypes` for ChaCha20-Poly1305 when available, with pure-python fallback.
- State written atomically to `~/.local/state/omclip/`. Settings in `~/.config/omclip/settings`.

**Hardware platform & limitations.**
- Developed and tested on an older Intel MacBook Air (MacBookAir6,2 / Core i5-4250U) running Linux without a T2/Secure Enclave chip.
- Apple Continuity pairing/pairing-verify and Rapport crypto operate standardly in software (RSA/Curve25519/AES-GCM/ChaCha20-Poly1305), but hardware-dependent aspects like Secure Enclave keychain extraction and T2-specific AWDL quirks differ on Apple Silicon and T2 Macs.
