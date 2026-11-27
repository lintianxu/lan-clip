<div align="center">

# LanClip (局域网快传)

**Cross-Platform End-to-End Encrypted LAN Clipboard & File Transfer for macOS, Windows & Android**

[简体中文](README.md) | English

![Platforms](https://img.shields.io/badge/Platforms-macOS%20%7C%20Windows%20%7C%20Android-007AFF?style=flat-square)
![Encryption](https://img.shields.io/badge/Crypto-X25519%20%2B%20Ed25519%20%2B%20AES--256--GCM-FF9500?style=flat-square)
![Zero Cloud](https://img.shields.io/badge/Server-Zero%20Cloud%20%7C%20Zero%20SSH-34C759?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

</div>

Want fast, private clipboard and file sharing across **macOS (even with different Apple IDs)**, **Windows**, and **Android** on the same Wi-Fi without cloud accounts, USB cables, or enabling SSH / Remote Login?

**LanClip** is a zero-cloud, native multi-platform LAN transfer tool. Pair any two devices once with a **one-time 6-digit verification code**, build your trusted device list, and send **end-to-end encrypted clipboard text and streaming files** in one click.

---

## Why LanClip?

| Feature | Cloud Chat / Notes | Plaintext LAN Tools | System SSH / Remote Login | **LanClip** |
| :--- | :---: | :---: | :---: | :---: |
| **macOS + Windows + Android** | Needs shared cloud login | Varies | Poor mobile/Windows UX | ✅ **Native 3-platform interop** |
| **100% LAN-only (zero cloud)** | ❌ Cloud relays | ✅ | ✅ | ✅ **Direct peer-to-peer** |
| **Encrypted clipboard transfers** | Provider-dependent | ❌ **Plaintext** | ✅ | ✅ **Per-transfer PFS** |
| **Encrypted file transfers** | Provider-dependent | ❌ **Often plaintext** | ✅ | ✅ **Metadata + chunks + ACK encrypted** |
| **No SSH / OS password exposure** | ✅ | ✅ | ❌ **Opens OS shell** | ✅ **Zero shell/disk access** |
| **Safe overwrite-free saving** | ❌ Cloud history | Varies | Script-dependent | ✅ **RAM clipboard / unique filenames** |

---

## Core Advantage: End-to-End Encrypted Text & File Transfers

> **Are file transfers also encrypted?**
> **Yes — 100% end-to-end encrypted.** Every transfer (both clipboard text and streaming files) establishes a fresh ephemeral `Curve25519 (X25519)` key agreement authenticated by mutual `Ed25519` signatures before sending any data. File metadata (**filename, file size, chunk size**), every **256 KB chunk**, the **SHA-256 integrity manifest**, and the final **receipt ACK** are all encrypted with `AES-256-GCM` and deterministic sequence nonces.

```mermaid
sequenceDiagram
    autonumber
    participant B as Initiator (Mac / Win / Android)
    participant A as Code Host (Mac / Win / Android)

    Note over A,B: Phase 1: One-Time 6-Digit Pairing (180s TTL · 1-time · 5-attempt lockout)
    B->>A: PAIR_INIT (Ephemeral X25519 + Ed25519 Identity + NonceB)
    A-->>B: PAIR_CHALLENGE (Ephemeral X25519 + Ed25519 Identity + NonceA + Salt)
    Note over B: X25519 DH + PBKDF2-HMAC-SHA256 (100,000 rounds) + HKDF<br/>Initiator proves code first
    B->>A: PAIR_PROOF_B (HMAC-SHA256 transcript proof)
    Note over A: Consumes code; pins mutual Ed25519 keys into device list
    A-->>B: PAIR_PROOF_A (Mutual confirmation)

    Note over A,B: Phase 2A: Encrypted Clipboard (Memory-Only, <= 1 MB)
    A->>B: CLIP_INIT / CLIP_CHALLENGE (Fresh X25519 + Mutual Ed25519 Signatures)
    A->>B: CLIP_PAYLOAD -> CLIP_ACK (AES-256-GCM, direct to system pasteboard)

    Note over A,B: Phase 2B: Streaming Encrypted File Transfer (256 KB Chunks, <= 4 GB)
    A->>B: FILE_INIT / FILE_CHALLENGE (Fresh X25519 + Mutual Ed25519 Signatures)
    A->>B: FILE_META (Encrypted fileName, fileSize, chunkSize)
    B-->>A: FILE_READY (Encrypted ACK; prepares isolated .part file)
    loop Each 256 KB chunk
        A->>B: FILE_CHUNK #i (Deterministic seq nonce + AES-256-GCM)
    end
    A->>B: FILE_FINISH (Encrypted totalChunks + SHA-256 checksum)
    B-->>A: FILE_ACK (Verified -> atomic move into Downloads/LanClip)
```

---

## Downloads & Quick Start

Grab pre-built binaries for all three platforms from [Releases](https://github.com/lintianxu/lan-clip/releases):

- **macOS (`LanClip-v3.0.0-macOS-universal.zip`)**: Universal App (`局域网快传.app`) for Apple Silicon & Intel (macOS 13+). Click Dock icon to send clipboard; drag files onto the app icon to send files.
  - First launch after download/AirDrop: run `xattr -cr /Applications/局域网快传.app` if quarantined, and allow **Local Network** permission.
- **Windows (`LanClip-v3.0.0-Windows-x64.exe`)**: Single portable Win32 tray binary (~4.2 MB, Windows 10/11 x64). Left-click tray icon to send clipboard; right-click to send files, switch peers, or toggle receiver.
  - First launch: click **More info → Run anyway** on SmartScreen and allow Private Network access in Windows Firewall.
- **Android (`LanClip-v3.0.0-Android.apk`)**: Native Material app (Android 8.0+). Supports sending phone clipboard, multi-file/photo picker, quick text composer box, Android Share Sheet (`ACTION_SEND` / `ACTION_SEND_MULTIPLE`), and foreground receiver toggle.

---

## Repository Layout & Cross-Platform Tests

All three native clients verify against the shared test suite in [protocol/test_vectors.json](protocol/test_vectors.json) and run automated CI builds on every push via [build-and-release.yml](.github/workflows/build-and-release.yml):

- [protocol/SPEC.md](protocol/SPEC.md) — Exact binary protocol specification (`LC2\x01`)
- [macos/](macos) — Swift client (`AppKit` + `Network` + `CryptoKit`)
- [windows/](windows) — Zero-CGo Go client (`golang.org/x/{crypto,net,sys}` + Win32 tray)
- [android/](android) — Native Kotlin client (`BouncyCastle` + AndroidX Material + `NsdManager`)

See [SECURITY.md](SECURITY.md) for the full threat model and [CONTRIBUTING.md](CONTRIBUTING.md) for build/test instructions.
