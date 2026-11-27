# LanClip Protocol v3 (`LC2\x01`) Specification

This document defines the exact wire format, cryptographic primitives, key schedules, and security invariants shared across **macOS (Swift)**, **Windows (Go)**, and **Android (Kotlin)**.

All three platforms are verified against `protocol/test_vectors.json`.

---

## 1. Transport, Discovery & Framing

- **Transport**: TCP over IPv4 or IPv6 (default listening port `47821`, ephemeral fallback if port is occupied).
- **Discovery**: mDNS / DNS-SD service type `_lanclip._tcp.` (`local.`) with TXT keys:
  - `id`: 16-hex local `deviceID`
  - `name`: UTF-8 display name
  - `pairing`: `"1"` while a 6-digit pairing session is active, else `"0"`
  - `port`: decimal listening TCP port
- **Frame Header (9 bytes)** followed by `length` body bytes:
  - Bytes `0..3`: Magic `0x4C 0x43 0x32 0x01` (`"LC2\x01"`)
  - Byte `4`: `msgType` (`uint8`)
  - Bytes `5..8`: `length` (`uint32` big-endian), must satisfy `0 <= length <= 1_100_000`
  - Bytes `9 ..< 9+length`: Frame payload

### Message Types
| Code | Name | Direction | Description |
| :--- | :--- | :--- | :--- |
| `0x01` | `pairInit` | B → A | Initiator ephemeral X25519 + Ed25519 identity + NonceB |
| `0x02` | `pairChallenge` | A → B | Host ephemeral X25519 + Ed25519 identity + NonceA + PBKDF2 Salt |
| `0x03` | `pairProofB` | B → A | Initiator HMAC-SHA256 proof of 6-digit code |
| `0x04` | `pairProofA` | A → B | Host HMAC-SHA256 confirmation |
| `0x0F` | `pairError` | Either | JSON `{ "message": "..." }` |
| `0x11` | `clipInit` | S → R | Ephemeral X25519 + NonceA + Ed25519 signature |
| `0x12` | `clipChallenge` | R → S | Ephemeral X25519 + NonceB + Ed25519 signature |
| `0x13` | `clipPayload` | S → R | JSON `{ "combinedB64": "<nonce12 || ciphertext || tag16>" }` |
| `0x14` | `clipAck` | R → S | JSON `{ "combinedB64": "<nonce12 || ciphertext || tag16>" }` |
| `0x1F` | `clipError` | Either | JSON `{ "message": "..." }` |
| `0x21` | `fileInit` | S → R | Ephemeral X25519 + NonceA + Ed25519 signature |
| `0x22` | `fileChallenge` | R → S | Ephemeral X25519 + NonceB + Ed25519 signature |
| `0x23` | `fileMeta` | S → R | Encrypted `seq=0` JSON `{ fileName, fileSize, chunkSize }` |
| `0x24` | `fileReady` | R → S | Encrypted `seq=0xFFFFFFFFFFFFFFFD` `"OK"` |
| `0x25` | `fileChunk` | S → R | `uint64_be(chunkIndex) || AES-GCM(seq=chunkIndex)` |
| `0x26` | `fileFinish` | S → R | Encrypted `seq=0xFFFFFFFFFFFFFFFE` JSON `{ sha256Hex, totalChunks }` |
| `0x27` | `fileAck` | R → S | Encrypted `seq=0xFFFFFFFFFFFFFFFF` JSON `{ savedName }` |
| `0x2F` | `fileError` | Either | JSON `{ "message": "..." }` |

---

## 2. LAN IP Allowlist & Receiver Gate

Receivers MUST validate the remote peer's IP before parsing payload bytes:
- **Allowed IPv4**:
  - `10.0.0.0/8`
  - `172.16.0.0/12`
  - `192.168.0.0/16`
  - `127.0.0.0/8` (loopback)
  - `169.254.0.0/16` (link-local)
- **Explicitly Rejected IPv4**: `198.18.0.0/15` (proxy/Clash TUN virtual interfaces) and all public IPv4 ranges.
- **Allowed IPv6**: `::1`, `fe80::/10`, `fc00::/7`, and `::ffff:a.b.c.d` where `a.b.c.d` passes the IPv4 allowlist.

---

## 3. Pairing Handshake (One-Time 6-Digit Code)

- Code generation: cryptographically random 6 ASCII digits (`000000`–`999999`), 180s TTL, single-use, permanently invalidated after 5 failed verification attempts.
- Key derivation:
  - `dh = X25519(myEphPriv, peerEphPub)` (32 bytes)
  - `pwKey = PBKDF2-HMAC-SHA256(password: codeUTF8, salt: salt16, rounds: 100000, len: 32)`
  - `transcript = SHA256("LANCLIP-PAIR-v2" || aDeviceID || "|" || bDeviceID || aSignPub || bSignPub || aEphPub || bEphPub || nonceA || nonceB || salt)`
  - `macKey = HKDF-SHA256(ikm: dh || pwKey, salt: salt, info: "lanclip-pair-mac-v2", len: 32)`
  - `proofB = HMAC-SHA256(key: macKey, msg: "PROOF-B" || transcript)`
  - `proofA = HMAC-SHA256(key: macKey, msg: "PROOF-A" || transcript)`
- Host A verifies `proofB` BEFORE consuming the code, replying with `proofA`, and storing B's `Ed25519` public key. B verifies `proofA` before storing A's `Ed25519` public key.

---

## 4. Clipboard Transfer (v2-compatible)

- `initSigned = "LANCLIP-CLIP-INIT-v2" || senderID || "|" || receiverID || ephPubA || nonceA`
- `chalSigned = "LANCLIP-CLIP-CHAL-v2" || receiverID || "|" || senderID || ephPubA || nonceA || ephPubB || nonceB`
- `txHash = SHA256("LANCLIP-CLIP-TX-v2" || senderID || "|" || receiverID || ephPubA || nonceA || ephPubB || nonceB)`
- `sessionKey = HKDF-SHA256(ikm: X25519(ephPriv, peerEphPub), salt: txHash, info: "lanclip-aes-gcm-v2", len: 32)`
- `clipPayload` (`combinedB64`): CryptoKit combined AES-256-GCM box (`nonce12 || ciphertext || tag16`) with AAD `"PAYLOAD" || txHash`. Plaintext UTF-8 `1 .. 1_048_576` bytes.
- `clipAck` (`combinedB64`): CryptoKit combined AES-256-GCM box (`nonce12 || ciphertext || tag16`) with AAD `"ACK" || txHash`, plaintext `"OK"`.

---

## 5. Streaming File Transfer (`v3`)

- `initSigned = "LANCLIP-FILE-INIT-v3" || senderID || "|" || receiverID || ephPubA || nonceA`
- `chalSigned = "LANCLIP-FILE-CHAL-v3" || receiverID || "|" || senderID || ephPubA || nonceA || ephPubB || nonceB`
- `txHash = SHA256("LANCLIP-FILE-TX-v3" || senderID || "|" || receiverID || ephPubA || nonceA || ephPubB || nonceB)`
- `dh = X25519(ephPriv, peerEphPub)`
- `sessionKey = HKDF-SHA256(ikm: dh, salt: txHash, info: "lanclip-file-gcm-v3", len: 32)`
- `nonceBase = HKDF-SHA256(ikm: dh, salt: txHash, info: "lanclip-file-nonce-v3", len: 12)`
- Deterministic nonce for `seq: uint64`:
  - `nonce(seq)[0..3] = nonceBase[0..3]`
  - `nonce(seq)[4..11] = bigEndianUInt64Bytes(bigEndianUInt64(nonceBase[4..11]) ^ seq)`
- Raw GCM payload encoding in `0x23`, `0x24`, `0x25`, `0x26`, `0x27`: `ciphertext || tag16` (no 12-byte nonce prefix).
- Sequences & AADs:
  - `0x23 fileMeta`: `seq = 0`, `aad = "FILE-META" || txHash`, JSON `{ fileName, fileSize, chunkSize }` (`fileSize <= 4_294_967_296`, `chunkSize <= 262_144`).
  - `0x24 fileReady`: `seq = 0xFFFFFFFFFFFFFFFD`, `aad = "FILE-READY" || txHash`, plaintext `"OK"`.
  - `0x25 fileChunk`: `chunkIndex = 1 .. totalChunks` (`seq = chunkIndex`), frame body = `uint64_be(chunkIndex) || AES-GCM(aad: "FILE-CHUNK" || uint64_be(chunkIndex) || txHash)`. Receiver rejects out-of-order `chunkIndex` or `bytesWritten > fileSize`.
  - `0x26 fileFinish`: `seq = 0xFFFFFFFFFFFFFFFE`, `aad = "FILE-FINISH" || txHash`, JSON `{ sha256Hex, totalChunks }`. Receiver checks `bytesWritten == fileSize`, `chunksReceived == totalChunks`, and constant-time lowercase hex SHA-256 match.
  - `0x27 fileAck`: `seq = 0xFFFFFFFFFFFFFFFF`, `aad = "FILE-ACK" || txHash`, JSON `{ savedName }`.

### Filename Sanitization & Non-Overwriting Save Rules
1. Extract basename across both `/` and `\` path separators.
2. Strip ASCII control characters (`< 0x20`, `0x7F`) and Windows-forbidden characters (`< > : " / \ | ? *`).
3. Trim leading/trailing spaces and `.` (and reject `.` / `..`).
4. Check Windows reserved stem names (`CON`, `PRN`, `AUX`, `NUL`, `COM1`..`COM9`, `LPT1`..`LPT9`, case-insensitive). If empty or reserved, fall back to `"received_file"`.
5. Truncate valid UTF-8 cleanly to at most `180` UTF-8 bytes.
6. Write into a temporary `.part` file inside `Downloads/LanClip/`, verify SHA-256, and atomically move to a deduplicated path (`name.ext`, `name (1).ext`, `name (2).ext`, ...) — never overwriting existing files. Delete `.part` on any error.
