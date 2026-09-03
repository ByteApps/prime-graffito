# Third-party libraries

Direct dependencies of this app and the companion web pages (`notes-core` and `graffito-core` are git dependencies on [ByteApps/graffito](https://github.com/ByteApps/graffito), where their own THIRD-PARTY.md lists theirs). The complete transitive list (with exact versions) is pinned in [`Cargo.lock`](Cargo.lock).

## Rust crates

| Library | Version | License | Used for |
|---|---|---|---|
| [notes-core](https://github.com/ByteApps/graffito/tree/main/notes-core) | pinned git rev | MIT OR Apache-2.0 | The PNTE protocol: key derivation, envelope, sealing, ECDH, taproot tx build/sign, sync bundles — one crate shared with the graffito Mac/mobile app (its direct dependencies are listed there) |
| [graffito-core](https://github.com/ByteApps/graffito/tree/main/graffito-core) | same pinned git rev | MIT OR Apache-2.0 | Shared UI-free policy (compose Security copy, `seclabel`) rendered identically by both apps |
| [getrandom](https://crates.io/crates/getrandom) | 0.2 | MIT OR Apache-2.0 | Entropy source (see vendored override below) |
| [serde](https://crates.io/crates/serde) / [serde_json](https://crates.io/crates/serde_json) | 1 | MIT OR Apache-2.0 | State persistence |
| [hex](https://crates.io/crates/hex) | 0.4 | MIT OR Apache-2.0 | Hex encoding (txids, exports) |
| [log](https://crates.io/crates/log) | 0.4 | MIT OR Apache-2.0 | Logging facade |

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
