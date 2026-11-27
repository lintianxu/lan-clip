# Contributing to LanClip

Thank you for helping improve **LanClip**!

## Design Principles
1. **Zero Third-Party Dependencies**: Stick strictly to Apple system frameworks (`AppKit`, `Network`, `CryptoKit`, `CommonCrypto`, `Security`) so the codebase stays small, fast to audit, and dependency-free.
2. **macOS 13+ Universal Compatibility**: All changes must compile cleanly with `-swift-version 5` for both `arm64-apple-macosx13.0` and `x86_64-apple-macosx13.0`.
3. **Security First**:
   - Never log or persist clipboard payloads to disk or notification banners.
   - Never weaken LAN IP allowlist enforcement or signature/key verification order.
   - Never access macOS Keychain or ship default secrets/certificates in the repository.

## Development Workflow
1. Make your changes in `Sources/`.
2. Build the Universal Binary and verify signing:
   ```sh
   sh build.sh
   ```
3. Run the 7-case end-to-end protocol & security test suite (required before opening a PR):
   ```sh
   swiftc -O -swift-version 5 -parse-as-library \
     -framework Network -framework CryptoKit -framework Security \
     Sources/Protocol.swift Sources/NetworkEngine.swift Tests/ProtocolTest.swift \
     -o /tmp/lanclip_test && /tmp/lanclip_test && rm -f /tmp/lanclip_test
   ```
4. Ensure `git status` contains no `build/`, `.DS_Store`, or personal environment files.
