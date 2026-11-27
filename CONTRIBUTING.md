# Contributing to LanClip

Thank you for helping improve **LanClip** across **macOS**, **Windows**, and **Android**!

## Design Principles
1. **Minimal Dependencies**:
   - **macOS (`macos/`)**: Zero external dependencies — Apple system frameworks only (`AppKit`, `Network`, `CryptoKit`, `CommonCrypto`, `Security`), compiled with `-swift-version 5` targeting `macos13.0` (`arm64` + `x86_64`).
   - **Windows (`windows/`)**: Pure Go (`CGO_ENABLED=0`) using stdlib + official `golang.org/x/{crypto,net,sys}` and Win32 APIs.
   - **Android (`android/`)**: Native Kotlin + AndroidX Material + `org.bouncycastle:bcprov-jdk18on`.
2. **Protocol Parity**: All wire or cryptographic updates must be reflected in [protocol/SPEC.md](protocol/SPEC.md) and verified identically across Swift, Go, and Kotlin using [protocol/test_vectors.json](protocol/test_vectors.json).
3. **Security First**: Never persist clipboard plaintext, never weaken LAN IP filtering or Ed25519 pre-verification, and never allow received files to escape or overwrite files inside `Downloads/LanClip`.

## Running Tests Before a PR
```sh
# macOS (Swift)
swiftc -O -swift-version 5 -parse-as-library \
  -framework Network -framework CryptoKit -framework Security \
  macos/Sources/Protocol.swift macos/Sources/NetworkEngine.swift macos/Tests/ProtocolTest.swift \
  -o /tmp/lanclip_test && /tmp/lanclip_test && rm -f /tmp/lanclip_test

# Windows (Go)
cd windows && go test -v ./...

# Android (Kotlin JVM tests)
cd android && gradle test
```
