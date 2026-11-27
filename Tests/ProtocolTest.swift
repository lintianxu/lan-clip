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

func runAllTests() throws {
    // 1. IP Allowlist Unit Tests
    must(isAllowedIPv4Bytes((192, 168, 1, 10)), "192.168.1.10 should be allowed")
    must(isAllowedIPv4Bytes((10, 0, 0, 1)), "10.0.0.1 should be allowed")
    must(isAllowedIPv4Bytes((172, 16, 0, 1)), "172.16.0.1 should be allowed")
    must(isAllowedIPv4Bytes((127, 0, 0, 1)), "127.0.0.1 should be allowed")
    must(isAllowedIPv4Bytes((169, 254, 1, 1)), "169.254.1.1 should be allowed")
    must(!isAllowedIPv4Bytes((198, 18, 0, 1)), "198.18.0.1 (Clash TUN) must be rejected")
    must(!isAllowedIPv4Bytes((198, 19, 255, 254)), "198.19.255.254 must be rejected")
    must(!isAllowedIPv4Bytes((8, 8, 8, 8)), "8.8.8.8 must be rejected")
    must(!isAllowedIPv4Bytes((1, 1, 1, 1)), "1.1.1.1 must be rejected")
    print("[1/7] IP allowlist guard OK")

    let tmpDir = FileManager.default.temporaryDirectory
        .appendingPathComponent("lanclip_test_\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: tmpDir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: tmpDir) }

    let portAExpected = pickFreePort()
    let portBExpected = pickFreePort()

    let engA = try LanClipEngine(
        stateURL: tmpDir.appendingPathComponent("a/state.json"),
        displayName: "Mac-A",
        preferredPort: portAExpected,
        advertiseBonjour: false
    )
    let engB = try LanClipEngine(
        stateURL: tmpDir.appendingPathComponent("b/state.json"),
        displayName: "Mac-B",
        preferredPort: portBExpected,
        advertiseBonjour: false
    )
    let engRogue = try LanClipEngine(
        stateURL: tmpDir.appendingPathComponent("c/state.json"),
        displayName: "Rogue-C",
        preferredPort: 0,
        advertiseBonjour: false
    )
    defer {
        engA.shutdown()
        engB.shutdown()
        engRogue.shutdown()
    }

    // 2. Start A's pairing session so A binds port
    var code1 = ""
    let genSem = DispatchSemaphore(value: 0)
    engA.startPairingCodeSession { code, _ in
        code1 = code
        genSem.signal()
    }
    must(genSem.wait(timeout: .now() + 5) == .success, "A startPairingCodeSession timed out")

    let waitReady: (LanClipEngine) -> UInt16 = { eng in
        for _ in 0..<60 {
            let p = eng.listeningPort()
            if p > 0 { return p }
            Thread.sleep(forTimeInterval: 0.05)
        }
        return 0
    }
    let portA = waitReady(engA)
    must(portA > 0, "Engine A did not bind port")
    print("[2/7] Host A listening on port \(portA) with code generated")

    // 3. Verify 5 wrong attempts lock out code1 (and 6th try with real code1 fails!)
    let pairSync: (LanClipEngine, String, UInt16, String) -> Result<PairedPeer, Error> = { eng, host, port, code in
        let sem = DispatchSemaphore(value: 0)
        var out: Result<PairedPeer, Error>!
        eng.pairWithEndpoint(endpoint: nil, fallbackHost: host, fallbackPort: port, code: code) { res in
            out = res
            sem.signal()
        }
        must(sem.wait(timeout: .now() + 15) == .success, "pairWithEndpoint timed out")
        return out
    }

    let wrongCode = (code1 == "000000") ? "999999" : "000000"
    for i in 1...5 {
        let r = pairSync(engB, "127.0.0.1", portA, wrongCode)
        if case .success = r {
            must(false, "Wrong code unexpectedly succeeded on attempt \(i)")
        }
    }
    let afterLock = pairSync(engB, "127.0.0.1", portA, code1)
    if case .success = afterLock {
        must(false, "Locked-out code1 still worked after 5 failures!")
    }
    print("[3/7] 5-attempt brute-force lockout OK")

    // 4. Fresh pairing code on A + B pairs with A -> verify mutual Ed25519 keys saved
    var code2 = ""
    let genSem2 = DispatchSemaphore(value: 0)
    engA.startPairingCodeSession { code, _ in
        code2 = code
        genSem2.signal()
    }
    must(genSem2.wait(timeout: .now() + 5) == .success, "A second pairing session timed out")
    let portA2 = waitReady(engA)
    must(portA2 > 0, "Engine A port missing after lockout")

    engB.start()
    let pairRes = pairSync(engB, "127.0.0.1", portA2, code2)
    guard case .success(let peerOnB) = pairRes else {
        if case .failure(let e) = pairRes {
            must(false, "Valid pairing failed: \(e.localizedDescription)")
        }
        must(false, "Valid pairing failed")
        return
    }
    must(peerOnB.deviceID == engA.currentIdentity().deviceID, "B saved wrong A deviceID")
    must(engA.currentPeer()?.deviceID == engB.currentIdentity().deviceID, "A saved wrong B deviceID")
    let portB = waitReady(engB)
    must(portB > 0, "B should automatically start listening after pairing")
    print("[4/7] Bidirectional 6-digit code pairing OK (A <-> B mutual Ed25519 saved)")

    // 5. Bidirectional encrypted clipboard transfer A -> B and B -> A
    var recvOnB: (String, String)?
    var recvOnA: (String, String)?
    let semB = DispatchSemaphore(value: 0)
    let semA = DispatchSemaphore(value: 0)
    engB.onTextReceived = { text, from in
        recvOnB = (text, from)
        semB.signal()
    }
    engA.onTextReceived = { text, from in
        recvOnA = (text, from)
        semA.signal()
    }

    let sendSync: (LanClipEngine, String) -> Result<(Int, String), Error> = { eng, text in
        let sem = DispatchSemaphore(value: 0)
        var out: Result<(Int, String), Error>!
        eng.sendText(text) { res in
            out = res
            sem.signal()
        }
        must(sem.wait(timeout: .now() + 10) == .success, "sendText timed out")
        return out
    }

    let msgAtoB = "你好Mac mini！测试中文、换行\n和表情😀🚀"
    let rAB = sendSync(engA, msgAtoB)
    guard case .success = rAB else {
        if case .failure(let e) = rAB { must(false, "A->B send failed: \(e.localizedDescription)") }
        must(false, "A->B send failed")
        return
    }
    must(semB.wait(timeout: .now() + 3) == .success, "B did not receive text")
    must(recvOnB?.0 == msgAtoB, "B received corrupted text")
    must(recvOnB?.1 == "Mac-A", "B received wrong sender name")

    let msgBtoA = "MacBook 收到回传测试 ✅ 12345"
    let rBA = sendSync(engB, msgBtoA)
    guard case .success = rBA else {
        if case .failure(let e) = rBA { must(false, "B->A send failed: \(e.localizedDescription)") }
        must(false, "B->A send failed")
        return
    }
    must(semA.wait(timeout: .now() + 3) == .success, "A did not receive text")
    must(recvOnA?.0 == msgBtoA, "A received corrupted text")
    must(recvOnA?.1 == "Mac-B", "A received wrong sender name")
    print("[5/7] Bidirectional AES-256-GCM UTF-8/Emoji transfer OK")

    // 6. Rogue Engine C (spoofing A's deviceID) is rejected by B
    let rogueSem = DispatchSemaphore(value: 0)
    var rogueRejected = false
    let rogueConn = NWConnection(host: "127.0.0.1", port: NWEndpoint.Port(rawValue: portB)!, using: .tcp)
    rogueConn.stateUpdateHandler = { st in
        if case .ready = st {
            let fakeKey = try! engRogue.currentIdentity().signingKey()
            let eph = Curve25519.KeyAgreement.PrivateKey()
            let nonce = randomBytes(16)
            let sig = try! fakeKey.signature(for: clipInitSignData(
                senderID: engA.currentIdentity().deviceID,
                receiverID: engB.currentIdentity().deviceID,
                ephPubA: eph.publicKey.rawRepresentation,
                nonceA: nonce
            ))
            let fakeInit = ClipInitMsg(
                senderDeviceID: engA.currentIdentity().deviceID,
                ephPubAB64: eph.publicKey.rawRepresentation.base64EncodedString(),
                nonceAB64: nonce.base64EncodedString(),
                sigAB64: sig.base64EncodedString()
            )
            writeJSONFrame(connection: rogueConn, type: .clipInit, value: fakeInit) { _ in
                readFrame(connection: rogueConn) { res in
                    switch res {
                    case .success(let (mt, _)):
                        rogueRejected = (mt == .clipError)
                    case .failure:
                        rogueRejected = true
                    }
                    rogueConn.cancel()
                    rogueSem.signal()
                }
            }
        }
    }
    rogueConn.start(queue: DispatchQueue.global())
    must(rogueSem.wait(timeout: .now() + 5) == .success && rogueRejected, "Rogue impersonation was not rejected!")
    print("[6/7] Rogue Ed25519 impersonation rejection OK")

    // 7. Receiver OFF closes listener cleanly; Receiver ON restores A -> B transfer
    engB.setReceiverEnabled(false)
    for _ in 0..<40 {
        if engB.listeningPort() == 0 { break }
        Thread.sleep(forTimeInterval: 0.05)
    }
    must(engB.listeningPort() == 0, "Engine B did not close port when receiver disabled")
    let rOff = sendSync(engA, "should fail while off")
    if case .success = rOff {
        must(false, "Send succeeded while receiver B was turned OFF!")
    }

    engB.setReceiverEnabled(true)
    let portB2 = waitReady(engB)
    must(portB2 == portB, "Engine B did not reopen expected port \(portB)")
    let rOn = sendSync(engA, "back online!")
    guard case .success = rOn else {
        if case .failure(let e) = rOn { must(false, "A->B failed after B re-enabled: \(e.localizedDescription)") }
        must(false, "A->B failed after B re-enabled")
        return
    }
    print("[7/7] Receiver toggle OFF/ON lifecycle OK")
    print("ALL 7 PROTOCOL TESTS PASSED")
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
