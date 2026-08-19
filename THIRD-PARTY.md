# Third-party libraries

Direct dependencies of this app, its `notes-core` library, and the companion web pages. The complete transitive list (with exact versions) is pinned in [`Cargo.lock`](Cargo.lock).

## Rust crates

| Library | Version | License | Used for |
|---|---|---|---|
| [k256](https://crates.io/crates/k256) | 0.13 | Apache-2.0 OR MIT | secp256k1 math: BIP341 taproot tweak, BIP340 Schnorr signing, ECDH, and (`ecdsa` feature) RFC6979 deterministic ECDSA for BIP143 P2WPKH spending-wallet signing |
| [sha2](https://crates.io/crates/sha2) | 0.10 | MIT OR Apache-2.0 | SHA-256 (sighashes, tagged hashes) |
| [hkdf](https://crates.io/crates/hkdf) | 0.12 | MIT OR Apache-2.0 | Key derivation (identity, encryption, directed-note keys) |
| [hmac](https://crates.io/crates/hmac) | 0.12 | MIT OR Apache-2.0 | HMAC for derivation |
| [pbkdf2](https://crates.io/crates/pbkdf2) | 0.12 | MIT OR Apache-2.0 | BIP-39 mnemonic → seed (recovery seeds) |
| [ripemd](https://crates.io/crates/ripemd) | 0.1 | MIT OR Apache-2.0 | BIP-32 key fingerprints (recovery seeds) |
| [chacha20poly1305](https://crates.io/crates/chacha20poly1305) | 0.10 | Apache-2.0 OR MIT | XChaCha20-Poly1305 sealing of private notes |
| [bech32](https://crates.io/crates/bech32) | 0.11 | MIT | Taproot addresses (BIP350) |
| [getrandom](https://crates.io/crates/getrandom) | 0.2 | MIT OR Apache-2.0 | Entropy source (see vendored override below) |
| [miniz_oxide](https://crates.io/crates/miniz_oxide) | 0.8 | MIT OR Zlib OR Apache-2.0 | Deflate decompression of scanned bundle payloads |
| [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) | 1 | MIT OR Apache-2.0 | Sync-bundle JSON and state persistence |
| [zeroize](https://crates.io/crates/zeroize) | 1 | Apache-2.0 OR MIT | Wiping secrets from memory |
| [hex](https://crates.io/crates/hex) | 0.4 | MIT OR Apache-2.0 | Hex encoding (txids, exports) |
| [log](https://crates.io/crates/log) | 0.4 | MIT OR Apache-2.0 | Logging facade |
| [bitcoin](https://crates.io/crates/bitcoin) (dev) | 0.32 | CC0-1.0 | Host-test cross-check of tx serialization/sighashes/signatures against libsecp256k1 — never a device dependency |
| [foundation-ur](https://crates.io/crates/foundation-ur) (dev) | 0.4 | MIT | Verifies the companion's UR encoder against the exact decoder the KeyOS scanner runs |
| [bip39](https://crates.io/crates/bip39) (dev) | 2 | CC0-1.0 | Host-test cross-check of our ported BIP-39 against an independent implementation |

## Vendored code

| Component | Origin | Role |
|---|---|---|
| `vendor/getrandom/` | KeyOS source (getrandom 0.2 fork) | Entropy override: hardware TRNG server on KeyOS builds, stock behavior on host |
| `vendor/security-api/` | KeyOS v1.2.1 source, adapted to SDK 0.4.0 conventions | `os/security` API client (`GetAppSeed`) |

## Companion (JavaScript, vendored in `companion/`)

| Library | License | Used for |
|---|---|---|
| [jsQR](https://github.com/cozmo/jsQR) (`jsqr.js`) | Apache-2.0 | Camera QR decoding in the browser |
| [qrcode-generator](https://github.com/kazuhikoarase/qrcode-generator) (`qrcode-gen.js`) | MIT | QR rendering of sync bundles |
| `ur.js` | project code (GPL-3.0-or-later) | Hand-rolled BC-UR encoder, byte-identical to foundation-ur |

## Foundation SDK / KeyOS platform

Provided by the installed Foundation SDK (path dependencies, not crates.io):

| Component | Role |
|---|---|
| `server` (KeyOS) | App runtime, KeyOS service messaging, filesystem API |
| `xous-api-log` | Log output to the KeyOS log server |
| `slint-keyos-platform` (+ `-build`) | [Slint](https://slint.dev) UI runtime, QR rendering, and build integration for KeyOS |
| `foundation-themes` | Design tokens and light/dark theming |

The Slint UI toolkit itself is licensed under GPL-3.0-only OR the Slint
Royalty-free / commercial licenses. **This app elects the GPL**, which is why
it is GPL-3.0-or-later. That is not a free choice: section 3 of the Slint
Royalty-free license excludes embedded systems, and a Passport Prime is one, so
on-device the GPL is the only option that costs nothing. KeyOS's own API crates
(`server`, `fs`, `crypto`, `security`, ...) are GPL-3.0-or-later as well. Taking
this app closed-source would require a paid Slint license *and* a resolution of
the KeyOS side.
