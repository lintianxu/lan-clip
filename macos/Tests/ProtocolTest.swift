import Foundation
import Network
import CryptoKit
import Darwin

func must(_ cond: Bool, _ msg: String) {
    if !cond {
        fputs("TEST FAILED: \(msg)\n", stderr)
        exit(1)
    }
}

func fromHex(_ hex: String) -> Data {
    var out = Data()
    var i = hex.startIndex
    while i < hex.endIndex {
        let j = hex.index(i, offsetBy: 2)
        out.append(UInt8(hex[i..<j], radix: 16)!)
        i = j
    }
    return out
}

func toHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
}

func pickFreePort() -> UInt16 {
    let fd = Darwin.socket(AF_INET, SOCK_STREAM, 0)
    must(fd >= 0, "socket() failed")
    defer { Darwin.close(fd) }
    var addr = sockaddr_in()
    addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
    addr.sin_family = sa_family_t(AF_INET)
    addr.sin_port = 0
    addr.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))
    let bindRes = withUnsafePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
        }
    }
    must(bindRes == 0, "bind() failed")
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    let nameRes = withUnsafeMutablePointer(to: &addr) {
        $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
            Darwin.getsockname(fd, $0, &len)
        }
    }
    must(nameRes == 0, "getsockname() failed")
    return UInt16(bigEndian: addr.sin_port)
}

func verifyVectorsFile() throws {
    let candidates = [
        URL(fileURLWithPath: "protocol/test_vectors.json"),
        URL(fileURLWithPath: "../protocol/test_vectors.json"),
        URL(fileURLWithPath: FileManager.default.homeDirectoryForCurrentUser.path)
            .appendingPathComponent(".gemini/antigravity/scratch/lan-clip/protocol/test_vectors.json")
    ]
    guard let vecURL = candidates.first(where: { FileManager.default.fileExists(atPath: $0.path) }) else {
        must(false, "Cannot find protocol/test_vectors.json")
        return
    }
    let data = try Data(contentsOf: vecURL)
    let root = try JSONSerialization.jsonObject(with: data) as! [String: Any]

    let ed = root["ed25519"] as! [String: String]
    let pub = try Curve25519.Signing.PublicKey(rawRepresentation: fromHex(ed["pubHex"]!))
    must(pub.isValidSignature(fromHex(ed["sigHex"]!), for: fromHex(ed["msgHex"]!)), "ed25519 vector invalid")

    let pv = root["pairing"] as! [String: String]
    let aEphPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: fromHex(pv["aEphPrivHex"]!))
    let bEphPub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: fromHex(pv["bEphPubHex"]!))
    let shared = try aEphPriv.sharedSecretFromKeyAgreement(with: bEphPub)
    let pwKey = try pbkdf2SHA256(code: pv["code"]!, salt: fromHex(pv["saltHex"]!))
    must(toHex(pwKey) == pv["pwKeyHex"]!, "pbkdf2 vector mismatch")
    let tx = computePairTranscript(
        aDeviceID: pv["aDeviceID"]!, bDeviceID: pv["bDeviceID"]!,
        aSignPub: fromHex(pv["aSignPubHex"]!), bSignPub: fromHex(pv["bSignPubHex"]!),
        aEphPub: fromHex(pv["aEphPubHex"]!), bEphPub: fromHex(pv["bEphPubHex"]!),
        nonceA: fromHex(pv["nonceAHex"]!), nonceB: fromHex(pv["nonceBHex"]!),
        salt: fromHex(pv["saltHex"]!)
    )
    must(toHex(tx) == pv["transcriptHex"]!, "pair transcript mismatch")
    let macKey = derivePairMacKey(sharedSecret: shared, pwKey: pwKey, salt: fromHex(pv["saltHex"]!))
    must(verifyPairProof(fromHex(pv["proofBHex"]!), label: "PROOF-B", transcript: tx, macKey: macKey), "proofB mismatch")
    must(verifyPairProof(fromHex(pv["proofAHex"]!), label: "PROOF-A", transcript: tx, macKey: macKey), "proofA mismatch")

    let cv = root["clipboard"] as! [String: String]
    let clipTx = clipTranscriptHash(
        senderID: cv["senderID"]!, receiverID: cv["receiverID"]!,
        ephPubA: fromHex(cv["ephPubAHex"]!), nonceA: fromHex(cv["nonceAHex"]!),
        ephPubB: fromHex(cv["ephPubBHex"]!), nonceB: fromHex(cv["nonceBHex"]!)
    )
    must(toHex(clipTx) == cv["txHashHex"]!, "clip txHash mismatch")
    let clipKey = deriveClipSessionKey(sharedSecret: shared, transcriptHash: clipTx)
    let clipOpen = try openClipData(Data(base64Encoded: cv["combinedB64"]!)!, aadLabel: "PAYLOAD", transcriptHash: clipTx, key: clipKey)
    must(toHex(clipOpen) == cv["plainHex"]!, "clip decrypt vector mismatch")

    let fv = root["file"] as! [String: String]
    let fileTx = fileTranscriptHash(
        senderID: fv["senderID"]!, receiverID: fv["receiverID"]!,
        ephPubA: fromHex(fv["ephPubAHex"]!), nonceA: fromHex(fv["nonceAHex"]!),
        ephPubB: fromHex(fv["ephPubBHex"]!), nonceB: fromHex(fv["nonceBHex"]!)
    )
    must(toHex(fileTx) == fv["txHashHex"]!, "file txHash mismatch")
    let (fileKey, nonceBase) = deriveFileSessionKeys(sharedSecret: shared, transcriptHash: fileTx)
    must(toHex(nonceBase) == fv["nonceBaseHex"]!, "file nonceBase mismatch")

    let metaOpen = try openFileRaw(ciphertextAndTag: fromHex(fv["metaCipherHex"]!), key: fileKey, nonceBase: nonceBase, seq: UInt64(fv["metaSeq"]!)!, aad: fileAAD(label: "FILE-META", transcriptHash: fileTx))
    must(toHex(metaOpen) == fv["metaPlainHex"]!, "file meta vector mismatch")
    let c1Open = try openFileRaw(ciphertextAndTag: fromHex(fv["chunk1CipherHex"]!), key: fileKey, nonceBase: nonceBase, seq: 1, aad: fileAAD(label: "FILE-CHUNK", seqPrefix: 1, transcriptHash: fileTx))
    must(toHex(c1Open) == fv["chunk1PlainHex"]!, "file chunk1 vector mismatch")
    let c2Open = try openFileRaw(ciphertextAndTag: fromHex(fv["chunk2CipherHex"]!), key: fileKey, nonceBase: nonceBase, seq: 2, aad: fileAAD(label: "FILE-CHUNK", seqPrefix: 2, transcriptHash: fileTx))
    must(toHex(c2Open) == fv["chunk2PlainHex"]!, "file chunk2 vector mismatch")
    let finOpen = try openFileRaw(ciphertextAndTag: fromHex(fv["finishCipherHex"]!), key: fileKey, nonceBase: nonceBase, seq: UInt64(fv["finishSeq"]!)!, aad: fileAAD(label: "FILE-FINISH", transcriptHash: fileTx))
    must(toHex(finOpen) == fv["finishPlainHex"]!, "file finish vector mismatch")
    let ackOpen = try openFileRaw(ciphertextAndTag: fromHex(fv["ackCipherHex"]!), key: fileKey, nonceBase: nonceBase, seq: UInt64(fv["ackSeq"]!)!, aad: fileAAD(label: "FILE-ACK", transcriptHash: fileTx))
    must(toHex(ackOpen) == fv["ackPlainHex"]!, "file ack vector mismatch")
}

func runAllTests() throws {
    // 1. IP Allowlist Guard
    must(isAllowedIPv4Bytes((192, 168, 1, 10)), "192.168.1.10 should be allowed")
    must(isAllowedIPv4Bytes((10, 0, 0, 1)), "10.0.0.1 should be allowed")
    must(isAllowedIPv4Bytes((172, 16, 0, 1)), "172.16.0.1 should be allowed")
    must(isAllowedIPv4Bytes((127, 0, 0, 1)), "127.0.0.1 should be allowed")
    must(isAllowedIPv4Bytes((169, 254, 1, 1)), "169.254.1.1 should be allowed")
    must(!isAllowedIPv4Bytes((198, 18, 0, 1)), "198.18.0.1 (Clash TUN) must be rejected")
    must(!isAllowedIPv4Bytes((198, 19, 255, 254)), "198.19.255.254 must be rejected")
    must(!isAllowedIPv4Bytes((8, 8, 8, 8)), "8.8.8.8 must be rejected")
    print("[1/10] IP allowlist guard OK")

    // 2. Shared Cross-Platform Cryptographic Test Vectors
    try verifyVectorsFile()
    print("[2/10] Shared test_vectors.json verification OK")

    // 3. Filename Sanitization & Path-Traversal Prevention
    must(sanitizeReceivedFileName("../../etc/passwd") == "passwd", "traversal unix")
    must(sanitizeReceivedFileName("..\\..\\Windows\\System32\\evil.exe") == "evil.exe", "traversal win")
    must(sanitizeReceivedFileName("CON.txt") == "received_file", "CON.txt reserved")
    must(sanitizeReceivedFileName("nul") == "received_file", "nul reserved")
    must(sanitizeReceivedFileName(".hidden_secret") == "hidden_secret", "leading dot")
    must(sanitizeReceivedFileName("...") == "received_file", "dots only")
    must(sanitizeReceivedFileName("a<b>c:d\"e|f?g*h.txt") == "abcdefgh.txt", "forbidden chars")
    let longName = String(repeating: "中", count: 100) + ".txt"
    let sanitizedLong = sanitizeReceivedFileName(longName)
    must(sanitizedLong.utf8.count <= 180 && !sanitizedLong.isEmpty, "utf8 length cap")
    print("[3/10] Filename sanitization & traversal prevention OK")

    let tmpDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("lanclip_v3_test_\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tmpDir) }

    let portA = pickFreePort()
    let portB = pickFreePort()
    let portC = pickFreePort()

    let engA = try LanClipEngine(
        stateURL: tmpDir.appendingPathComponent("a/state.json"),
        downloadsURL: tmpDir.appendingPathComponent("a/dl", isDirectory: true),
        displayName: "Mac-A",
        preferredPort: portA,
        advertiseBonjour: false
    )
    let engB = try LanClipEngine(
        stateURL: tmpDir.appendingPathComponent("b/state.json"),
        downloadsURL: tmpDir.appendingPathComponent("b/dl", isDirectory: true),
        displayName: "Win-B",
        preferredPort: portB,
        advertiseBonjour: false
    )
    let engC = try LanClipEngine(
        stateURL: tmpDir.appendingPathComponent("c/state.json"),
        downloadsURL: tmpDir.appendingPathComponent("c/dl", isDirectory: true),
        displayName: "Android-C",
        preferredPort: portC,
        advertiseBonjour: false
    )
    let engRogue = try LanClipEngine(
        stateURL: tmpDir.appendingPathComponent("r/state.json"),
        downloadsURL: tmpDir.appendingPathComponent("r/dl", isDirectory: true),
        displayName: "Rogue",
        preferredPort: 0,
        advertiseBonjour: false
    )
    defer {
        engA.shutdown(); engB.shutdown(); engC.shutdown(); engRogue.shutdown()
    }

    let waitReady: (LanClipEngine) -> UInt16 = { eng in
        for _ in 0..<60 {
            let p = eng.listeningPort()
            if p > 0 { return p }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return 0
    }

    let genCodeSync: (LanClipEngine) -> String = { eng in
        let sem = DispatchSemaphore(value: 0)
        var out = ""
        eng.startPairingCodeSession { code, _ in
            out = code
            sem.signal()
        }
        must(sem.wait(timeout: .now() + 5) == .success, "genCode timed out")
        return out
    }

    let pairSync: (LanClipEngine, String, UInt16, String) -> Result<PairedPeer, Error> = { eng, host, port, code in
        let sem = DispatchSemaphore(value: 0)
        var out: Result<PairedPeer, Error>!
        eng.pairWithEndpoint(endpoint: nil, fallbackHost: host, fallbackPort: port, code: code) { res in
            out = res
            sem.signal()
        }
        must(sem.wait(timeout: .now() + 15) == .success, "pair timed out")
        return out
    }

    // 4. 5-attempt lockout
    let code1 = genCodeSync(engA)
    must(waitReady(engA) == portA, "A did not bind \(portA)")
    let wrongCode = (code1 == "000000") ? "999999" : "000000"
    for _ in 1...5 {
        if case .success = pairSync(engB, "127.0.0.1", portA, wrongCode) {
            must(false, "wrong code succeeded")
        }
    }
    if case .success = pairSync(engB, "127.0.0.1", portA, code1) {
        must(false, "locked code1 still worked")
    }
    print("[4/10] 5-attempt brute-force lockout OK")

    // 5. Multi-device pairing: A <-> B and A <-> C
    engB.start()
    engC.start()
    let code2 = genCodeSync(engA)
    guard case .success = pairSync(engB, "127.0.0.1", portA, code2) else {
        must(false, "A <-> B pairing failed")
        return
    }
    let code3 = genCodeSync(engA)
    guard case .success = pairSync(engC, "127.0.0.1", portA, code3) else {
        must(false, "A <-> C pairing failed")
        return
    }
    must(engA.pairedPeers().count == 2, "A should have 2 paired peers")
    must(waitReady(engB) == portB, "B did not bind \(portB)")
    must(waitReady(engC) == portC, "C did not bind \(portC)")
    print("[5/10] Multi-device pairing (A<->B & A<->C) OK")

    // 6. Bidirectional multi-device clipboard transfer
    let sendClipSync: (LanClipEngine, String, String?) -> Result<(Int, String), Error> = { eng, text, pid in
        let sem = DispatchSemaphore(value: 0)
        var out: Result<(Int, String), Error>!
        eng.sendText(text, to: pid) { res in out = res; sem.signal() }
        must(sem.wait(timeout: .now() + 8) == .success, "sendText timed out")
        return out
    }

    var gotB = ""; var gotC = ""; var gotA = ""
    let sB = DispatchSemaphore(value: 0); let sC = DispatchSemaphore(value: 0); let sA = DispatchSemaphore(value: 0)
    engB.onTextReceived = { t, _ in gotB = t; sB.signal() }
    engC.onTextReceived = { t, _ in gotC = t; sC.signal() }
    engA.onTextReceived = { t, _ in gotA = t; sA.signal() }

    guard case .success = sendClipSync(engA, "发给B的文字😀", engB.currentIdentity().deviceID) else {
        must(false, "A->B clip failed"); return
    }
    must(sB.wait(timeout: .now() + 3) == .success && gotB == "发给B的文字😀", "B clip mismatch")

    guard case .success = sendClipSync(engA, "发给C的文字🚀", engC.currentIdentity().deviceID) else {
        must(false, "A->C clip failed"); return
    }
    must(sC.wait(timeout: .now() + 3) == .success && gotC == "发给C的文字🚀", "C clip mismatch")

    guard case .success = sendClipSync(engC, "C回传A的剪贴板✅", nil) else {
        must(false, "C->A clip failed"); return
    }
    must(sA.wait(timeout: .now() + 3) == .success && gotA == "C回传A的剪贴板✅", "A clip mismatch")
    print("[6/10] Multi-device bidirectional encrypted clipboard OK")

    // 7. Streaming multi-chunk encrypted file transfer (~700 KB across 3 chunks) A -> B and B -> A
    let srcPayload = randomBytes(700_000)
    let srcFileA = tmpDir.appendingPathComponent("测试视频片段.bin")
    try srcPayload.write(to: srcFileA)

    var recvFileB: URL?
    let fSemB = DispatchSemaphore(value: 0)
    engB.onFileReceived = { url, _, _ in recvFileB = url; fSemB.signal() }

    let sendFileSync: (LanClipEngine, URL, String?) -> Result<(String, String), Error> = { eng, u, pid in
        let sem = DispatchSemaphore(value: 0)
        var out: Result<(String, String), Error>!
        eng.sendFile(at: u, to: pid) { res in out = res; sem.signal() }
        must(sem.wait(timeout: .now() + 15) == .success, "sendFile timed out")
        return out
    }

    guard case .success(let (savedB, _)) = sendFileSync(engA, srcFileA, engB.currentIdentity().deviceID) else {
        must(false, "A->B multi-chunk file failed"); return
    }
    must(fSemB.wait(timeout: .now() + 5) == .success, "B onFileReceived missing")
    must(savedB == "测试视频片段.bin", "unexpected saved name: \(savedB)")
    let readBackB = try Data(contentsOf: recvFileB!)
    must(readBackB == srcPayload, "A->B file bytes mismatch")

    // B -> A back
    var recvFileA: URL?
    let fSemA = DispatchSemaphore(value: 0)
    engA.onFileReceived = { url, _, _ in recvFileA = url; fSemA.signal() }
    guard case .success = sendFileSync(engB, recvFileB!, nil) else {
        must(false, "B->A file failed"); return
    }
    must(fSemA.wait(timeout: .now() + 5) == .success, "A onFileReceived missing")
    must((try Data(contentsOf: recvFileA!)) == srcPayload, "B->A file bytes mismatch")
    print("[7/10] Bidirectional multi-chunk streaming encrypted file transfer OK")

    // 8. 0-byte empty file & non-overwriting deduplication
    let emptyFile = tmpDir.appendingPathComponent("report.txt")
    try Data().write(to: emptyFile)
    let fSemB2 = DispatchSemaphore(value: 0)
    var dedup1: URL?
    engB.onFileReceived = { url, _, _ in dedup1 = url; fSemB2.signal() }
    guard case .success(let (s1, _)) = sendFileSync(engA, emptyFile, engB.currentIdentity().deviceID) else {
        must(false, "0-byte send failed"); return
    }
    must(fSemB2.wait(timeout: .now() + 3) == .success && s1 == "report.txt", "0-byte filename mismatch")
    must((try Data(contentsOf: dedup1!)).isEmpty, "0-byte file should be empty")

    // Now overwrite source with non-empty data and send again -> must become "report (1).txt" without overwriting original!
    try Data("second version".utf8).write(to: emptyFile)
    let fSemB3 = DispatchSemaphore(value: 0)
    var dedup2: URL?
    engB.onFileReceived = { url, _, _ in dedup2 = url; fSemB3.signal() }
    guard case .success(let (s2, _)) = sendFileSync(engA, emptyFile, engB.currentIdentity().deviceID) else {
        must(false, "dedup send failed"); return
    }
    must(fSemB3.wait(timeout: .now() + 3) == .success && s2 == "report (1).txt", "expected report (1).txt, got \(s2)")
    must((try Data(contentsOf: dedup1!)).isEmpty, "original report.txt was overwritten!")
    must((try Data(contentsOf: dedup2!)) == Data("second version".utf8), "dedup2 content mismatch")
    print("[8/10] 0-byte file & non-overwriting deduplication OK")

    // 9. Rogue Ed25519 signature rejection on both clipInit and fileInit
    let testRogue: (MsgType) -> Void = { mType in
        let rSem = DispatchSemaphore(value: 0)
        var rejected = false
        let rConn = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: portB)!, using: .tcp)
        rConn.stateUpdateHandler = { st in
            if case .ready = st {
                let fakeKey = try! engRogue.currentIdentity().signingKey()
                let eph = Curve25519.KeyAgreement.PrivateKey()
                let nonce = randomBytes(16)
                let signData = (mType == .clipInit)
                    ? clipInitSignData(senderID: engA.currentIdentity().deviceID, receiverID: engB.currentIdentity().deviceID, ephPubA: eph.publicKey.rawRepresentation, nonceA: nonce)
                    : fileInitSignData(senderID: engA.currentIdentity().deviceID, receiverID: engB.currentIdentity().deviceID, ephPubA: eph.publicKey.rawRepresentation, nonceA: nonce)
                let sig = try! fakeKey.signature(for: signData)
                let initMsg = ClipInitMsg(
                    senderDeviceID: engA.currentIdentity().deviceID,
                    ephPubAB64: eph.publicKey.rawRepresentation.base64EncodedString(),
                    nonceAB64: nonce.base64EncodedString(),
                    sigAB64: sig.base64EncodedString()
                )
                writeJSONFrame(connection: rConn, type: mType, value: initMsg) { _ in
                    readFrame(connection: rConn) { res in
                        switch res {
                        case .success(let (rt, _)):
                            rejected = (rt == .clipError || rt == .fileError)
                        case .failure:
                            rejected = true
                        }
                        rConn.cancel()
                        rSem.signal()
                    }
                }
            }
        }
        rConn.start(queue: DispatchQueue.global())
        must(rSem.wait(timeout: .now() + 5) == .success && rejected, "Rogue \(mType) not rejected")
    }
    testRogue(.clipInit)
    testRogue(.fileInit)
    print("[9/10] Rogue Ed25519 impersonation rejected on clipboard & file OK")

    // 10. Receiver toggle OFF/ON & single-peer removal
    engB.setReceiverEnabled(false)
    for _ in 0..<40 {
        if engB.listeningPort() == 0 { break }
        Thread.sleep(forTimeInterval: 0.05)
    }
    must(engB.listeningPort() == 0, "B did not close port")
    if case .success = sendClipSync(engA, "fail", engB.currentIdentity().deviceID) {
        must(false, "clip succeeded while B OFF")
    }
    engB.setReceiverEnabled(true)
    must(waitReady(engB) == portB, "B did not reopen \(portB)")
    guard case .success = sendClipSync(engA, "ok", engB.currentIdentity().deviceID) else {
        must(false, "clip failed after B ON"); return
    }
    engA.removePeer(engC.currentIdentity().deviceID)
    Thread.sleep(forTimeInterval: 0.1)
    must(engA.pairedPeers().count == 1 && engA.activePeer()?.deviceID == engB.currentIdentity().deviceID, "removePeer failed")
    print("[10/10] Receiver toggle OFF/ON & single-peer removal OK")
    print("ALL 10 MACOS V3 TESTS PASSED")
}

@main
struct ProtocolTestRunner {
    static func main() {
        DispatchQueue.global().async {
            do {
                try runAllTests()
                exit(0)
            } catch {
                fputs("TEST ERROR: \(error)\n", stderr)
                exit(1)
            }
        }
        dispatchMain()
    }
}
