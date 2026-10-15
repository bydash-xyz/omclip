# Acknowledgements

`omclip` is built upon the foundational reverse-engineering and open-source contributions of several projects and researchers:

* **[pyatv](https://github.com/postlund/pyatv)** (Pierre Ståhl & contributors)
  * Clean Python-native implementations and specifications for Apple's OPACK and TLV8 serialization formats and pairing primitives.
* **[OpenDrop / OWL (Open Wireless Link)](https://github.com/seemoo-lab/opendrop)** (Milan Stute, Alexander Heinrich, Bastian Bloessl, Matthias Hollick — Secure Mobile Networking Lab, TU Darmstadt)
  * Pioneer research and open implementations of the Apple Wireless Direct Link (AWDL) protocol, Apple Continuity framing, and AirDrop mutual authentication.
* **[airdrop-keychain-extractor](https://github.com/seemoo-lab/airdrop-keychain-extractor)** (Milan Stute — Secure Mobile Networking Lab, TU Darmstadt; GPL-3.0)
  * The approach for extracting the AirDrop Apple-ID identity (validation record, certificate, key) from the macOS keychain, including the required SIP/AMFI relaxation and `keychain-access-groups` entitlement. `omclip` does not bundle this tool; you supply your own credentials, extracted from your own Mac.
* **Apple Continuity & Rapport Research Community**
  * Research into `rapportd`, Companion Link, `_continuity._tcp` streaming, and Pair-Verify protocols.
* **OpenSSL Project**
  * Modern cryptographic primitives including ChaCha20-Poly1305 and X25519.
