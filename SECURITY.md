# Security Policy & Cryptographic Architecture

## 1. Threat Model

### In-Scope Threats Mitigated
- **Passive LAN Eavesdropping**: Mitigated by per-transfer ephemeral `Curve25519` (X25519) key exchange + `AES-256-GCM` authenticated encryption with transcript-bound AAD.
- **Active Impersonation / MITM on LAN**:
  - During pairing: Mitigated by binding ephemeral X25519 shared secrets with `PBKDF2-HMAC-SHA256` (100,000 rounds) of the 6-digit code and verifying mutual `HMAC-SHA256` proofs over the full identity/key/nonce transcript. The initiator proves knowledge of the code first (`PAIR_PROOF_B`) before the host replies (`PAIR_PROOF_A`).
  - During transfers: Mitigated by mutual `Ed25519` signature verification over fresh ephemeral keys and nonces **before** any clipboard payload is encrypted or transmitted, with no insecure fallback.
- **Online Brute-Forcing of the 6-Digit Pairing Code**: Mitigated by 180-second expiration, single-use invalidation upon first success, and immediate session destruction after 5 failed attempts.
- **Public Internet / Proxy TUN Exposure**: Mitigated by strict endpoint IP allowlisting (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, IPv6 `::1`, `fe80::/10`, `fc00::/7`), explicit rejection of `198.18.0.0/15`, and an explicit menu-bar receiver kill switch.
- **Remote OS Compromise**: Unlike SSH-based clipboard forwarding, LanClip exposes **no shell, file access, password login, or arbitrary command execution**. A paired peer can only push UTF-8 text (`<= 1 MB`) to `NSPasteboard.general`.

### Out-of-Scope Boundaries
- An attacker who already has local code execution or root access on one of the two Macs can read `~/.lan-clip/state.json` (`0600`) or read `NSPasteboard.general` directly.
- If a Mac is physically lost or compromised, use **「清除当前配对」** on the remaining Mac immediately to revoke trust.

## 2. Local Key & Data Storage
- `~/.lan-clip/` is created with POSIX mode `0700`.
- `~/.lan-clip/state.json` is written atomically via `open(..., 0o600)` + `rename` and holds the device's `Ed25519` private key and paired peer's public key.
- macOS Keychain is never accessed or modified.
- Clipboard contents remain strictly in memory (`NSPasteboard.general`), never written to disk, logs, or notification center banners.

## 3. Reporting a Vulnerability
If you discover a security flaw in the protocol, IP validation, or framing logic, please open a private security advisory (or describe a minimal reproduction without leaking personal keys/data) in this repository.
