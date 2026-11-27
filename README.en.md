<div align="center">

# LanClip (局域网传文字)

**Zero-Dependency · End-to-End Encrypted · Native macOS LAN Clipboard Transfer**

[简体中文](README.md) | English

![macOS 13+](https://img.shields.io/badge/macOS-13.0%2B-007AFF?style=flat-square&logo=apple)
![Universal Binary](https://img.shields.io/badge/Arch-Apple%20Silicon%20%2B%20Intel-34C759?style=flat-square)
![Zero Dependencies](https://img.shields.io/badge/Dependencies-Zero-5856D6?style=flat-square)
![Encryption](https://img.shields.io/badge/Crypto-X25519%20%2B%20Ed25519%20%2B%20AES--256--GCM-FF9500?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-lightgrey?style=flat-square)

</div>

Have two Macs signed into **different Apple IDs** where Apple's Universal Clipboard doesn't work? **LanClip** is a tiny (~1.1 MB) zero-dependency native Swift macOS app that lets you send clipboard text directly between two Macs on the same LAN — **no cloud servers, no Remote Login (SSH), no manual certificate files**, just a **one-time 6-digit verification code** and end-to-end encryption on every transfer.

---

## Why LanClip?

| Feature | Cloud Chat / Notes | Plaintext LAN Tools | macOS Remote Login (SSH) | **LanClip** |
| :--- | :---: | :---: | :---: | :---: |
| **Works across different Apple IDs** | Needs shared account | ✅ | ✅ | ✅ |
| **100% LAN-only (zero cloud servers)** | ❌ | ✅ | ✅ | ✅ |
| **End-to-end encrypted transfers** | Provider-dependent | ❌ **Plaintext** | ✅ | ✅ **Per-transfer PFS** |
| **No SSH / shell exposure** | ✅ | ✅ | ❌ **Opens OS login** | ✅ **Zero shell capability** |
| **Memory-only (no disk / clipboard logs)** | ❌ Stored in cloud | Implementation-dependent | Script-dependent | ✅ **Direct to RAM pasteboard** |
| **Frictionless pairing** | Account login | Unauthenticated broadcast | CLI key exchange | ✅ **One-time 6-digit code** |

---

## Core Advantage: End-to-End Encrypted Transmission

LanClip is designed from the ground up with zero third-party dependencies using only Apple's `CryptoKit`, `CommonCrypto`, `Security`, `Network`, and `AppKit`:

```mermaid
sequenceDiagram
    autonumber
    participant B as Initiator Mac B
    participant A as Code Host Mac A

    Note over A,B: Phase 1: One-Time 6-Digit Pairing (180s TTL / 5-attempt lockout)
    B->>A: PAIR_INIT (Ephemeral X25519 + Ed25519 Identity + NonceB)
    A-->>B: PAIR_CHALLENGE (Ephemeral X25519 + Ed25519 Identity + NonceA + Salt)
    Note over B: Derives shared key from X25519 + PBKDF2-HMAC-SHA256 (100k rounds)<br/>Initiator proves knowledge of the 6-digit code first
    B->>A: PAIR_PROOF_B (HMAC-SHA256 transcript proof)
    Note over A: Consumes code immediately; pins mutual Ed25519 public keys
    A-->>B: PAIR_PROOF_A (Mutual confirmation)

    Note over A,B: Phase 2: Clipboard Transfer (Fresh Ephemeral Keys Every Send)
    A->>B: CLIP_INIT (Fresh X25519 Public Key + Ed25519 Signature)
    Note over B: Verifies peer Ed25519 signature first
    B-->>A: CLIP_CHALLENGE (Fresh X25519 Public Key + Ed25519 Signature)
    Note over A: Verifies receiver Ed25519 signature BEFORE encrypting payload
    A->>B: CLIP_PAYLOAD (AES-256-GCM ciphertext with transcript AAD)
    B-->>A: CLIP_ACK (Encrypted receipt; writes directly to NSPasteboard)
```

### Security Highlights
1. **Brute-Force Resistant 6-Digit Pairing**:
   - Generated via `SecRandomCopyBytes` with unbiased rejection sampling; expires after **180 seconds**, **single-use**, and permanently **locks out after 5 failed attempts**.
   - Key agreement binds ephemeral `Curve25519` (X25519) DH with **100,000-round `PBKDF2-HMAC-SHA256`**, derived via `HKDF-SHA256`, and verified with mutual `HMAC-SHA256` transcript proofs (`PROOF-B` first). Both Macs store each other's long-term `Ed25519` public keys in one step.
2. **Per-Transfer Perfect Forward Secrecy (PFS)**:
   - Every clipboard send negotiates fresh ephemeral `X25519` keys, verifies mutual `Ed25519` signatures **before** transmitting any payload, and encrypts UTF-8 text (capped at **1 MB**) with `AES-256-GCM` bound to the handshake transcript hash.
3. **Strict LAN Allowlist & Instant Off Switch**:
   - Incoming connections are restricted to private/local IP ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, IPv6 `::1`, `fe80::/10`, `fc00::/7`), explicitly rejecting proxy TUN interfaces (`198.18.0.0/15`) and all public IPs.
   - Toggle the receiver off from the menu bar anytime (e.g., on public Wi-Fi) to cancel the listener and Bonjour advertisement completely.
4. **Memory-Only Clipboard Handling**:
   - Plaintext never touches disk, logs, or notification banners. Long-term device keys live solely in `~/.lan-clip/state.json` (`0600` inside `0700` directory) without touching macOS Keychain.

---

## Quick Start

1. **Download**: Grab `LanClip-v2.0.0-macOS-universal.zip` from [Releases](https://github.com/lintianxu/lan-clip/releases), unzip **`局域网传文字.app`** (Universal Binary for Apple Silicon & Intel, macOS 13+), and move it into `/Applications` on both Macs.
2. **First-Launch macOS Prompts** (ad-hoc signed open-source binary):
   - If copied via AirDrop/browser and macOS reports *"damaged and can't be opened"*, remove the quarantine attribute once in Terminal:
     ```sh
     xattr -cr /Applications/局域网传文字.app
     ```
   - When prompted for **Local Network** access, click **Allow** so Bonjour discovery and LAN transfers work.
3. **Pair Once & Send in One Click**:
   - Open the app on both Macs → click **"生成 6 位验证码"** on Mac A → click **"输入对方验证码配对"** on Mac B, select Mac A (or enter its LAN IP), and type the 6 digits.
   - Copy text on either Mac and click the Dock or Menu Bar icon to encrypt and push directly to the other Mac's clipboard (`⌘V` to paste).

---

## Build & Test from Source

Requires macOS 13+ with Xcode Command Line Tools (`swiftc`).

```sh
# Build Universal .app and release zip under build/
sh build.sh

# Build and install to ~/Desktop and ~/Applications
sh build.sh --install
```

Run the 7-case end-to-end protocol & security test suite (uses isolated temp directories and ephemeral localhost ports; never modifies `~/.lan-clip` or your real clipboard):

```sh
swiftc -O -swift-version 5 -parse-as-library \
  -framework Network -framework CryptoKit -framework Security \
  Sources/Protocol.swift Sources/NetworkEngine.swift Tests/ProtocolTest.swift \
  -o /tmp/lanclip_test && /tmp/lanclip_test && rm -f /tmp/lanclip_test
```

---

## Documentation & License

- Security Architecture & Threat Model: [SECURITY.md](SECURITY.md)
- Contributing Guidelines: [CONTRIBUTING.md](CONTRIBUTING.md)
- License: [MIT License](LICENSE)
