import Foundation
import Network
import CryptoKit
import CommonCrypto
import Security
import Darwin

let LANCLIP_MAGIC = Data([0x4C, 0x43, 0x32, 0x01])
let LANCLIP_DEFAULT_PORT: UInt16 = 47821
let LANCLIP_MAX_CLIP_BYTES = 1_048_576
let LANCLIP_MAX_FRAME_BYTES = 1_100_000
let LANCLIP_SERVICE_TYPE = "_lanclip._tcp"
let LANCLIP_PBKDF2_ROUNDS: UInt32 = 100_000

enum MsgType: UInt8 {
    case pairInit = 0x01
    case pairChallenge = 0x02
    case pairProofB = 0x03
    case pairProofA = 0x04
    case pairError = 0x0F

    case clipInit = 0x11
    case clipChallenge = 0x12
    case clipPayload = 0x13
    case clipAck = 0x14
    case clipError = 0x1F
}

enum ProtocolError: Error, LocalizedError {
    case invalidMagic
    case invalidMessageType
    case frameTooLarge
    case eof
    case cryptoFailure(String)
    case remoteError(String)

    var errorDescription: String? {
        switch self {
        case .invalidMagic:
            return "收到无效的数据包头"
        case .invalidMessageType:
            return "收到未知的协议消息类型"
        case .frameTooLarge:
            return "数据包超出安全大小上限"
        case .eof:
            return "对方提前断开了连接"
        case .cryptoFailure(let msg):
            return msg
        case .remoteError(let msg):
            return msg
        }
    }
}

struct DeviceIdentity: Codable {
    let deviceID: String
    var displayName: String
    let ed25519PrivateKeyB64: String

    func signingKey() throws -> Curve25519.Signing.PrivateKey {
        guard let raw = Data(base64Encoded: ed25519PrivateKeyB64) else {
            throw ProtocolError.cryptoFailure("本机身份密钥损坏")
        }
        return try Curve25519.Signing.PrivateKey(rawRepresentation: raw)
    }

    static func generate(displayName: String) -> DeviceIdentity {
        let key = Curve25519.Signing.PrivateKey()
        let idBytes = randomBytes(8)
        let idHex = idBytes.map { String(format: "%02x", $0) }.joined()
        return DeviceIdentity(
            deviceID: idHex,
            displayName: displayName,
            ed25519PrivateKeyB64: key.rawRepresentation.base64EncodedString()
        )
    }
}

struct PairedPeer: Codable {
    let deviceID: String
    var displayName: String
    let ed25519PublicKeyB64: String
    var lastHost: String
    var lastPort: UInt16
    var pairedAt: Date

    func publicKey() throws -> Curve25519.Signing.PublicKey {
        guard let raw = Data(base64Encoded: ed25519PublicKeyB64) else {
            throw ProtocolError.cryptoFailure("对方身份公钥损坏")
        }
        return try Curve25519.Signing.PublicKey(rawRepresentation: raw)
    }
}

struct PersistedState: Codable {
    var identity: DeviceIdentity
    var peer: PairedPeer?
    var receiverEnabled: Bool
}

struct PairInitMsg: Codable {
    let bDeviceID: String
    let bDisplayName: String
    let bSignPubB64: String
    let bEphPubB64: String
    let nonceBB64: String
    let bListenPort: UInt16
}

struct PairChallengeMsg: Codable {
    let aDeviceID: String
    let aDisplayName: String
    let aSignPubB64: String
    let aEphPubB64: String
    let nonceAB64: String
    let saltB64: String
    let aListenPort: UInt16
}

struct PairProofMsg: Codable {
    let proofB64: String
}

struct WireErrorMsg: Codable {
    let message: String
}

struct ClipInitMsg: Codable {
    let senderDeviceID: String
    let ephPubAB64: String
    let nonceAB64: String
    let sigAB64: String
}

struct ClipChallengeMsg: Codable {
    let ephPubBB64: String
    let nonceBB64: String
    let sigBB64: String
}

struct ClipSealedMsg: Codable {
    let combinedB64: String
}

// MARK: - Random & Key Derivation

func randomBytes(_ count: Int) -> Data {
    var bytes = [UInt8](repeating: 0, count: count)
    let rc = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
    precondition(rc == errSecSuccess, "SecRandomCopyBytes failed")
    return Data(bytes)
}

func randomSixDigitCode() -> String {
    let bound: UInt32 = (UInt32.max / 1_000_000) * 1_000_000
    while true {
        let raw = randomBytes(4)
        let val = raw.withUnsafeBytes { ptr -> UInt32 in
            ptr.load(as: UInt32.self)
        }
        if val < bound {
            return String(format: "%06u", val % 1_000_000)
        }
    }
}

func pbkdf2SHA256(code: String, salt: Data, rounds: UInt32 = LANCLIP_PBKDF2_ROUNDS) throws -> Data {
    let codeData = Array(code.utf8)
    var derived = [UInt8](repeating: 0, count: 32)
    let status = codeData.withUnsafeBytes { passPtr in
        salt.withUnsafeBytes { saltPtr in
            CCKeyDerivationPBKDF(
                CCPBKDFAlgorithm(kCCPBKDF2),
                passPtr.bindMemory(to: Int8.self).baseAddress,
                codeData.count,
                saltPtr.bindMemory(to: UInt8.self).baseAddress,
                salt.count,
                CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                rounds,
                &derived,
                derived.count
            )
        }
    }
    guard status == kCCSuccess else {
        throw ProtocolError.cryptoFailure("密钥派生失败")
    }
    return Data(derived)
}

func computePairTranscript(
    aDeviceID: String,
    bDeviceID: String,
    aSignPub: Data,
    bSignPub: Data,
    aEphPub: Data,
    bEphPub: Data,
    nonceA: Data,
    nonceB: Data,
    salt: Data
) -> Data {
    var hasher = SHA256()
    hasher.update(data: Data("LANCLIP-PAIR-v2".utf8))
    hasher.update(data: Data(aDeviceID.utf8))
    hasher.update(data: Data("|".utf8))
    hasher.update(data: Data(bDeviceID.utf8))
    hasher.update(data: aSignPub)
    hasher.update(data: bSignPub)
    hasher.update(data: aEphPub)
    hasher.update(data: bEphPub)
    hasher.update(data: nonceA)
    hasher.update(data: nonceB)
    hasher.update(data: salt)
    return Data(hasher.finalize())
}

func derivePairMacKey(sharedSecret: SharedSecret, pwKey: Data, salt: Data) -> SymmetricKey {
    let ssData = sharedSecret.withUnsafeBytes { Data($0) }
    var ikmData = Data()
    ikmData.append(ssData)
    ikmData.append(pwKey)
    let ikm = SymmetricKey(data: ikmData)
    return HKDF<SHA256>.deriveKey(
        inputKeyMaterial: ikm,
        salt: salt,
        info: Data("lanclip-pair-mac-v2".utf8),
        outputByteCount: 32
    )
}

func computePairProof(label: String, transcript: Data, macKey: SymmetricKey) -> Data {
    var msg = Data(label.utf8)
    msg.append(transcript)
    let code = HMAC<SHA256>.authenticationCode(for: msg, using: macKey)
    return Data(code)
}

func verifyPairProof(_ proof: Data, label: String, transcript: Data, macKey: SymmetricKey) -> Bool {
    var msg = Data(label.utf8)
    msg.append(transcript)
    return HMAC<SHA256>.isValidAuthenticationCode(proof, authenticating: msg, using: macKey)
}

func clipInitSignData(senderID: String, receiverID: String, ephPubA: Data, nonceA: Data) -> Data {
    var data = Data("LANCLIP-CLIP-INIT-v2".utf8)
    data.append(Data(senderID.utf8))
    data.append(Data("|".utf8))
    data.append(Data(receiverID.utf8))
    data.append(ephPubA)
    data.append(nonceA)
    return data
}

func clipChallengeSignData(
    receiverID: String,
    senderID: String,
    ephPubA: Data,
    nonceA: Data,
    ephPubB: Data,
    nonceB: Data
) -> Data {
    var data = Data("LANCLIP-CLIP-CHAL-v2".utf8)
    data.append(Data(receiverID.utf8))
    data.append(Data("|".utf8))
    data.append(Data(senderID.utf8))
    data.append(ephPubA)
    data.append(nonceA)
    data.append(ephPubB)
    data.append(nonceB)
    return data
}

func clipTranscriptHash(
    senderID: String,
    receiverID: String,
    ephPubA: Data,
    nonceA: Data,
    ephPubB: Data,
    nonceB: Data
) -> Data {
    var hasher = SHA256()
    hasher.update(data: Data("LANCLIP-CLIP-TX-v2".utf8))
    hasher.update(data: Data(senderID.utf8))
    hasher.update(data: Data("|".utf8))
    hasher.update(data: Data(receiverID.utf8))
    hasher.update(data: ephPubA)
    hasher.update(data: nonceA)
    hasher.update(data: ephPubB)
    hasher.update(data: nonceB)
    return Data(hasher.finalize())
}

func deriveClipSessionKey(sharedSecret: SharedSecret, transcriptHash: Data) -> SymmetricKey {
    return sharedSecret.hkdfDerivedSymmetricKey(
        using: SHA256.self,
        salt: transcriptHash,
        sharedInfo: Data("lanclip-aes-gcm-v2".utf8),
        outputByteCount: 32
    )
}

func sealClipData(_ plain: Data, aadLabel: String, transcriptHash: Data, key: SymmetricKey) throws -> Data {
    var aad = Data(aadLabel.utf8)
    aad.append(transcriptHash)
    let box = try AES.GCM.seal(plain, using: key, authenticating: aad)
    guard let combined = box.combined else {
        throw ProtocolError.cryptoFailure("加密封装失败")
    }
    return combined
}

func openClipData(_ combined: Data, aadLabel: String, transcriptHash: Data, key: SymmetricKey) throws -> Data {
    var aad = Data(aadLabel.utf8)
    aad.append(transcriptHash)
    let box = try AES.GCM.SealedBox(combined: combined)
    return try AES.GCM.open(box, using: key, authenticating: aad)
}

// MARK: - Network Framing

func writeFrame(connection: NWConnection, type: MsgType, payload: Data, completion: @escaping (Error?) -> Void) {
    var packet = Data()
    packet.append(LANCLIP_MAGIC)
    packet.append(type.rawValue)
    var beLen = UInt32(payload.count).bigEndian
    withUnsafeBytes(of: &beLen) { packet.append(contentsOf: $0) }
    packet.append(payload)
    connection.send(content: packet, completion: .contentProcessed { err in
        completion(err)
    })
}

func writeJSONFrame<T: Encodable>(connection: NWConnection, type: MsgType, value: T, completion: @escaping (Error?) -> Void) {
    do {
        let data = try JSONEncoder().encode(value)
        writeFrame(connection: connection, type: type, payload: data, completion: completion)
    } catch {
        completion(error)
    }
}

private func readExactLoop(
    connection: NWConnection,
    remaining: Int,
    acc: Data,
    completion: @escaping (Result<Data, Error>) -> Void
) {
    if remaining == 0 {
        completion(.success(acc))
        return
    }
    connection.receive(minimumIncompleteLength: 1, maximumLength: remaining) { data, _, isComplete, error in
        if let error = error {
            completion(.failure(error))
            return
        }
        var next = acc
        if let chunk = data, !chunk.isEmpty {
            next.append(chunk)
        }
        let left = remaining - (data?.count ?? 0)
        if left == 0 {
            completion(.success(next))
            return
        }
        if isComplete || (data == nil || data!.isEmpty) {
            completion(.failure(ProtocolError.eof))
            return
        }
        readExactLoop(connection: connection, remaining: left, acc: next, completion: completion)
    }
}

func readFrame(connection: NWConnection, completion: @escaping (Result<(MsgType, Data), Error>) -> Void) {
    readExactLoop(connection: connection, remaining: 9, acc: Data()) { headerResult in
        switch headerResult {
        case .failure(let err):
            completion(.failure(err))
        case .success(let header):
            guard header.subdata(in: 0..<4) == LANCLIP_MAGIC else {
                completion(.failure(ProtocolError.invalidMagic))
                return
            }
            guard let msgType = MsgType(rawValue: header[4]) else {
                completion(.failure(ProtocolError.invalidMessageType))
                return
            }
            let len: UInt32 = header.subdata(in: 5..<9).withUnsafeBytes { ptr in
                UInt32(bigEndian: ptr.load(as: UInt32.self))
            }
            guard len <= UInt32(LANCLIP_MAX_FRAME_BYTES) else {
                completion(.failure(ProtocolError.frameTooLarge))
                return
            }
            readExactLoop(connection: connection, remaining: Int(len), acc: Data()) { bodyResult in
                switch bodyResult {
                case .failure(let err):
                    completion(.failure(err))
                case .success(let body):
                    completion(.success((msgType, body)))
                }
            }
        }
    }
}

// MARK: - LAN IP Security Guard

func isAllowedIPv4Bytes(_ b: (UInt8, UInt8, UInt8, UInt8)) -> Bool {
    // Explicitly reject Clash/benchmark TUN range 198.18.0.0/15
    if b.0 == 198 && (b.1 == 18 || b.1 == 19) {
        return false
    }
    // 10.0.0.0/8
    if b.0 == 10 { return true }
    // 172.16.0.0/12
    if b.0 == 172 && (b.1 >= 16 && b.1 <= 31) { return true }
    // 192.168.0.0/16
    if b.0 == 192 && b.1 == 168 { return true }
    // 127.0.0.0/8 (loopback)
    if b.0 == 127 { return true }
    // 169.254.0.0/16 (link-local)
    if b.0 == 169 && b.1 == 254 { return true }
    return false
}

func isAllowedIPv4Data(_ raw: Data) -> Bool {
    guard raw.count == 4 else { return false }
    return isAllowedIPv4Bytes((raw[0], raw[1], raw[2], raw[3]))
}

func isAllowedIPv6Data(_ raw: Data) -> Bool {
    guard raw.count == 16 else { return false }
    // ::1 loopback
    if raw.prefix(15).allSatisfy({ $0 == 0 }) && raw[15] == 1 {
        return true
    }
    // ::ffff:a.b.c.d IPv4-mapped
    let v4Prefix = Data([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    if raw.prefix(12) == v4Prefix {
        return isAllowedIPv4Data(Data(raw.suffix(4)))
    }
    // fe80::/10 link-local
    if raw[0] == 0xfe && (raw[1] & 0xc0) == 0x80 {
        return true
    }
    // fc00::/7 ULA
    if (raw[0] & 0xfe) == 0xfc {
        return true
    }
    return false
}

func isAllowedLANEndpoint(_ endpoint: NWEndpoint) -> Bool {
    guard case let .hostPort(host, _) = endpoint else {
        return false
    }
    switch host {
    case .ipv4(let v4):
        return isAllowedIPv4Data(v4.rawValue)
    case .ipv6(let v6):
        if let mapped = v6.asIPv4 {
            return isAllowedIPv4Data(mapped.rawValue)
        }
        return isAllowedIPv6Data(v6.rawValue)
    default:
        return false
    }
}

func extractIPString(from endpoint: NWEndpoint) -> String {
    guard case let .hostPort(host, _) = endpoint else {
        return ""
    }
    switch host {
    case .ipv4(let v4):
        let d = v4.rawValue
        guard d.count == 4 else { return "" }
        return "\(d[0]).\(d[1]).\(d[2]).\(d[3])"
    case .ipv6(let v6):
        if let mapped = v6.asIPv4 {
            let d = mapped.rawValue
            guard d.count == 4 else { return "" }
            return "\(d[0]).\(d[1]).\(d[2]).\(d[3])"
        }
        return ""
    default:
        return ""
    }
}

func detectLocalLANIP() -> String {
    var ifaddr: UnsafeMutablePointer<ifaddrs>?
    guard getifaddrs(&ifaddr) == 0, let firstAddr = ifaddr else {
        return ""
    }
    defer { freeifaddrs(ifaddr) }

    var candidates: [(iface: String, ip: String)] = []
    var ptr: UnsafeMutablePointer<ifaddrs>? = firstAddr
    while let cur = ptr {
        let flags = Int32(cur.pointee.ifa_flags)
        let isUp = (flags & IFF_UP) != 0
        let isLoopback = (flags & IFF_LOOPBACK) != 0
        if isUp && !isLoopback, let sa = cur.pointee.ifa_addr, sa.pointee.sa_family == UInt8(AF_INET) {
            var addr = sa.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { $0.pointee.sin_addr }
            var buf = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
            if inet_ntop(AF_INET, &addr, &buf, socklen_t(INET_ADDRSTRLEN)) != nil {
                let ip = String(cString: buf)
                let raw = withUnsafeBytes(of: &addr) { Data($0) }
                if isAllowedIPv4Data(raw) && !ip.hasPrefix("127.") && !ip.hasPrefix("169.254.") {
                    let iface = String(cString: cur.pointee.ifa_name)
                    candidates.append((iface, ip))
                }
            }
        }
        ptr = cur.pointee.ifa_next
    }

    for pref in ["en0", "en1", "en2", "en3"] {
        if let hit = candidates.first(where: { $0.iface == pref }) {
            return hit.ip
        }
    }
    return candidates.first?.ip ?? ""
}

// MARK: - State Persistence

func defaultStateURL() -> URL {
    let dir = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent(".lan-clip", isDirectory: true)
    return dir.appendingPathComponent("state.json", isDirectory: false)
}

func loadOrCreateState(at url: URL, defaultDisplayName: String) throws -> PersistedState {
    let dir = url.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)

    if FileManager.default.fileExists(atPath: url.path) {
        let data = try Data(contentsOf: url)
        let state = try JSONDecoder().decode(PersistedState.self, from: data)
        _ = try state.identity.signingKey()
        return state
    }

    let fresh = PersistedState(
        identity: DeviceIdentity.generate(displayName: defaultDisplayName),
        peer: nil,
        receiverEnabled: true
    )
    try saveState(fresh, to: url)
    return fresh
}

func saveState(_ state: PersistedState, to url: URL) throws {
    let dir = url.deletingLastPathComponent()
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
    try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: dir.path)

    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(state)

    let tmpURL = dir.appendingPathComponent(".state.tmp.\(UUID().uuidString)")
    let fd = Darwin.open(tmpURL.path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
    guard fd >= 0 else {
        throw ProtocolError.cryptoFailure("无法写入状态文件")
    }
    var writeErr: Int32 = 0
    data.withUnsafeBytes { rawBuf in
        guard let base = rawBuf.baseAddress else { return }
        var written = 0
        while written < rawBuf.count {
            let n = Darwin.write(fd, base.advanced(by: written), rawBuf.count - written)
            if n <= 0 {
                writeErr = errno
                break
            }
            written += n
        }
    }
    Darwin.close(fd)
    guard writeErr == 0 else {
        try? FileManager.default.removeItem(at: tmpURL)
        throw ProtocolError.cryptoFailure("写入状态文件失败 (\(writeErr))")
    }
    if Darwin.rename(tmpURL.path, url.path) != 0 {
        let err = errno
        try? FileManager.default.removeItem(at: tmpURL)
        throw ProtocolError.cryptoFailure("保存状态文件失败 (\(err))")
    }
}
