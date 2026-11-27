# Security Policy & Cryptographic Architecture (v3)

## 1. Threat Model

### In-Scope Threats Mitigated
- **Passive LAN Eavesdropping (Text & Files)**: Every clipboard transfer and every file transfer negotiates fresh ephemeral `Curve25519` (X25519) keys and derives unique `AES-256-GCM` session keys (`HKDF-SHA256`), guaranteeing Perfect Forward Secrecy. For streaming files, metadata (`fileName`, `fileSize`, `chunkSize`), every 256 KB chunk, the SHA-256 integrity manifest, and the receipt ACK are all encrypted and authenticated under deterministic sequence-derived GCM nonces (`nonceBase[0..3] || (tail64 ^ seq)`).
- **Active Impersonation / MITM on LAN**:
  - Pairing: Binds ephemeral X25519 DH with `PBKDF2-HMAC-SHA256` (100,000 rounds) of the 6-digit code and verifies mutual `HMAC-SHA256` transcript proofs (`PROOF-B` first, then `PROOF-A`).
  - Transfers: Mutual `Ed25519` signatures over fresh ephemeral keys and nonces are verified **before** encrypting or transmitting clipboard text or file metadata/chunks, with zero insecure fallback.
- **Online Brute-Forcing of the 6-Digit Pairing Code**: Cryptographically random 6-digit codes expire after 180 seconds, are consumed on first success, and lock out & self-destruct after 5 failed attempts.
- **Public Network / Proxy TUN Exposure**: Receivers strictly enforce a private/LAN IP allowlist (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `169.254.0.0/16`, IPv6 `::1`, `fe80::/10`, `fc00::/7`), explicitly rejecting `198.18.0.0/15` and public IPs. Each platform also provides an immediate receiver kill switch.
- **Path Traversal & File Overwrite Attacks**: Received filenames are stripped to basename, purged of control characters, Windows-forbidden characters (`<>:"/\|?*`), leading/trailing dots, and Windows reserved device names (`CON`, `PRN`, `AUX`, `NUL`, `COM1-9`, `LPT1-9`). Files stream into isolated temporary `.part` staging files inside `Downloads/LanClip/`, require exact `fileSize`, chunk count, and constant-time `SHA-256` verification before committing, and always auto-deduplicate (`name (1).ext`) rather than overwriting existing files.
- **Remote OS / Shell Compromise**: Unlike SSH-based tools, LanClip exposes zero shell, arbitrary command execution, or file-read capability.

### Out-of-Scope Boundaries
- An attacker who already possesses local code execution or administrator access on a paired device can inspect its local state or system clipboard/downloads folder directly.
- If a device is lost or untrusted, remove it immediately from the **Manage Devices** menu on your remaining devices to revoke its `Ed25519` trust entry.

## 2. Local State & Privacy Guarantees
- Desktop local state (`~/.lan-clip/state.json`) is stored atomically with `0600` file permissions inside a `0700` directory; Android stores `state.json` inside private app internal storage (`filesDir`).
- macOS Keychain is never touched.
- Clipboard plaintext never touches disk, log files, or notification banners.

## 3. Reporting a Vulnerability
Please report suspected security flaws via a private GitHub Security Advisory without including real keys or personal data.
