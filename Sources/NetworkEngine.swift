import Foundation
import Network
import CryptoKit

struct DiscoveredPeer: Equatable {
    let deviceID: String
    let displayName: String
    let isPairing: Bool
    let port: UInt16
    let endpoint: NWEndpoint
}

private struct ActivePairingSession {
    let code: String
    let expiresAt: Date
    var failedAttempts: Int
}

final class LanClipEngine {
    private let queue = DispatchQueue(label: "com.local.lanclip.engine")
    private let stateURL: URL
    private let preferredPort: UInt16
    private let advertiseBonjour: Bool
    private let connectionSem = DispatchSemaphore(value: 4)

    private var state: PersistedState
    private var listener: NWListener?
    private var actualPort: UInt16 = 0
    private var portFallbackAttempted = false

    private var browser: NWBrowser?
    private var discovered: [DiscoveredPeer] = []

    private var activePairing: ActivePairingSession?
    private var pairingTimer: DispatchSourceTimer?

    var onStateChanged: (() -> Void)?
    var onPeersDiscovered: (([DiscoveredPeer]) -> Void)?
    var onPairingCompleted: ((PairedPeer) -> Void)?
    var onPairingExpired: (() -> Void)?
    var onTextReceived: ((String, String) -> Void)?

    init(
        stateURL: URL = defaultStateURL(),
        displayName: String = Host.current().localizedName ?? ProcessInfo.processInfo.hostName,
        preferredPort: UInt16 = LANCLIP_DEFAULT_PORT,
        advertiseBonjour: Bool = true
    ) throws {
        self.stateURL = stateURL
        self.preferredPort = preferredPort
        self.advertiseBonjour = advertiseBonjour
        self.state = try loadOrCreateState(at: stateURL, defaultDisplayName: displayName)
    }

    // MARK: - Thread-safe State Queries

    func currentIdentity() -> DeviceIdentity {
        return queue.sync { state.identity }
    }

    func currentPeer() -> PairedPeer? {
        return queue.sync { state.peer }
    }

    func isReceiverEnabled() -> Bool {
        return queue.sync { state.receiverEnabled }
    }

    func listeningPort() -> UInt16 {
        return queue.sync { actualPort }
    }

    func discoveredPeers() -> [DiscoveredPeer] {
        return queue.sync { discovered }
    }

    // MARK: - Lifecycle

    func start() {
        queue.async {
            self.syncListenerLocked()
        }
    }

    func shutdown() {
        queue.sync {
            self.pairingTimer?.cancel()
            self.pairingTimer = nil
            self.activePairing = nil
            self.listener?.cancel()
            self.listener = nil
            self.actualPort = 0
            self.browser?.cancel()
            self.browser = nil
        }
    }

    func setReceiverEnabled(_ enabled: Bool) {
        queue.async {
            self.state.receiverEnabled = enabled
            try? saveState(self.state, to: self.stateURL)
            self.syncListenerLocked()
            self.notifyStateChanged()
        }
    }

    func clearPairing() {
        queue.async {
            self.state.peer = nil
            self.state.receiverEnabled = true
            try? saveState(self.state, to: self.stateURL)
            self.syncListenerLocked()
            self.notifyStateChanged()
        }
    }

    // MARK: - Pairing Code Session (Host Side)

    func startPairingCodeSession(completion: ((String, Date) -> Void)? = nil) {
        queue.async {
            self.pairingTimer?.cancel()
            let code = randomSixDigitCode()
            let expiresAt = Date().addingTimeInterval(180)
            self.activePairing = ActivePairingSession(code: code, expiresAt: expiresAt, failedAttempts: 0)

            let timer = DispatchSource.makeTimerSource(queue: self.queue)
            timer.schedule(deadline: .now() + 180)
            timer.setEventHandler { [weak self] in
                guard let self = self else { return }
                if self.activePairing != nil {
                    self.activePairing = nil
                    self.syncListenerLocked()
                    self.notifyStateChanged()
                    let cb = self.onPairingExpired
                    DispatchQueue.main.async { cb?() }
                }
            }
            timer.resume()
            self.pairingTimer = timer

            self.syncListenerLocked()
            self.notifyStateChanged()
            DispatchQueue.main.async {
                completion?(code, expiresAt)
            }
        }
    }

    func cancelPairingCodeSession() {
        queue.async {
            self.pairingTimer?.cancel()
            self.pairingTimer = nil
            self.activePairing = nil
            self.syncListenerLocked()
            self.notifyStateChanged()
        }
    }

    // MARK: - Bonjour Discovery

    func startDiscovery() {
        queue.async {
            self.browser?.cancel()
            self.discovered = []
            let params = NWParameters()
            params.includePeerToPeer = false
            let desc = NWBrowser.Descriptor.bonjourWithTXTRecord(type: LANCLIP_SERVICE_TYPE, domain: "local.")
            let b = NWBrowser(for: desc, using: params)
            b.browseResultsChangedHandler = { [weak self] results, _ in
                self?.handleBrowseResults(results)
            }
            b.start(queue: self.queue)
            self.browser = b
        }
    }

    func stopDiscovery() {
        queue.async {
            self.browser?.cancel()
            self.browser = nil
        }
    }

    private func handleBrowseResults(_ results: Set<NWBrowser.Result>) {
        let selfID = state.identity.deviceID
        var list: [DiscoveredPeer] = []
        for r in results {
            guard case let .service(name, _, _, _) = r.endpoint else { continue }
            var peerID = ""
            var peerName = name
            var isPairing = false
            var peerPort: UInt16 = LANCLIP_DEFAULT_PORT
            if case let .bonjour(txt) = r.metadata {
                if case let .string(v) = txt.getEntry(for: "id") {
                    peerID = v
                }
                if case let .string(v) = txt.getEntry(for: "name"), !v.isEmpty {
                    peerName = v
                }
                if case let .string(v) = txt.getEntry(for: "pairing") {
                    isPairing = (v == "1")
                }
                if case let .string(v) = txt.getEntry(for: "port"), let p = UInt16(v) {
                    peerPort = p
                }
            }
            if peerID.isEmpty || peerID == selfID { continue }
            list.append(DiscoveredPeer(
                deviceID: peerID,
                displayName: peerName,
                isPairing: isPairing,
                port: peerPort,
                endpoint: r.endpoint
            ))
        }
        list.sort {
            if $0.isPairing != $1.isPairing { return $0.isPairing && !$1.isPairing }
            return $0.displayName < $1.displayName
        }
        self.discovered = list
        let cb = self.onPeersDiscovered
        DispatchQueue.main.async { cb?(list) }
    }

    // MARK: - Listener Management

    private func shouldListenLocked() -> Bool {
        if activePairing != nil { return true }
        return state.peer != nil && state.receiverEnabled
    }

    private func buildTXTRecordLocked(port: UInt16) -> NWTXTRecord {
        return NWTXTRecord([
            "id": state.identity.deviceID,
            "name": state.identity.displayName,
            "pairing": activePairing != nil ? "1" : "0",
            "port": String(port)
        ])
    }

    private func syncListenerLocked() {
        let needed = shouldListenLocked()
        if !needed {
            listener?.cancel()
            listener = nil
            actualPort = 0
            portFallbackAttempted = false
            return
        }

        if let existing = listener {
            if advertiseBonjour && actualPort > 0 {
                existing.service = NWListener.Service(
                    name: state.identity.displayName,
                    type: LANCLIP_SERVICE_TYPE,
                    txtRecord: buildTXTRecordLocked(port: actualPort)
                )
            }
            return
        }

        startListenerLocked(port: preferredPort)
    }

    private func startListenerLocked(port: UInt16) {
        do {
            let params = NWParameters.tcp
            params.allowLocalEndpointReuse = true
            let nwPort: NWEndpoint.Port = (port == 0) ? .any : (NWEndpoint.Port(rawValue: port) ?? .any)
            let newListener = try NWListener(using: params, on: nwPort)

            if advertiseBonjour {
                newListener.service = NWListener.Service(
                    name: state.identity.displayName,
                    type: LANCLIP_SERVICE_TYPE,
                    txtRecord: buildTXTRecordLocked(port: port == 0 ? LANCLIP_DEFAULT_PORT : port)
                )
            }

            newListener.stateUpdateHandler = { [weak self, weak newListener] st in
                guard let self = self, let l = newListener, self.listener === l else { return }
                switch st {
                case .ready:
                    if let assigned = l.port?.rawValue {
                        self.actualPort = assigned
                        if self.advertiseBonjour {
                            l.service = NWListener.Service(
                                name: self.state.identity.displayName,
                                type: LANCLIP_SERVICE_TYPE,
                                txtRecord: self.buildTXTRecordLocked(port: assigned)
                            )
                        }
                        self.notifyStateChanged()
                    }
                case .failed:
                    if port != 0 && !self.portFallbackAttempted {
                        self.portFallbackAttempted = true
                        l.cancel()
                        self.listener = nil
                        self.startListenerLocked(port: 0)
                    }
                default:
                    break
                }
            }

            newListener.newConnectionHandler = { [weak self] conn in
                self?.handleIncomingConnection(conn)
            }

            newListener.start(queue: queue)
            self.listener = newListener
        } catch {
            if port != 0 && !portFallbackAttempted {
                portFallbackAttempted = true
                startListenerLocked(port: 0)
            }
        }
    }

    private func notifyStateChanged() {
        let cb = onStateChanged
        DispatchQueue.main.async { cb?() }
    }

    // MARK: - Incoming Connection Handler

    private func handleIncomingConnection(_ conn: NWConnection) {
        guard isAllowedLANEndpoint(conn.endpoint) else {
            conn.cancel()
            return
        }
        guard connectionSem.wait(timeout: .now()) == .success else {
            conn.cancel()
            return
        }

        let finish = { [weak self] in
            conn.cancel()
            self?.connectionSem.signal()
        }

        let timeoutWork = DispatchWorkItem {
            conn.cancel()
        }
        queue.asyncAfter(deadline: .now() + 5.0, execute: timeoutWork)

        conn.stateUpdateHandler = { [weak self] st in
            guard let self = self else { return }
            switch st {
            case .ready:
                readFrame(connection: conn) { result in
                    switch result {
                    case .failure:
                        timeoutWork.cancel()
                        finish()
                    case .success(let (msgType, payload)):
                        switch msgType {
                        case .pairInit:
                            self.handleIncomingPair(conn: conn, payload: payload, timeoutWork: timeoutWork, finish: finish)
                        case .clipInit:
                            self.handleIncomingClip(conn: conn, payload: payload, timeoutWork: timeoutWork, finish: finish)
                        default:
                            timeoutWork.cancel()
                            finish()
                        }
                    }
                }
            case .failed, .cancelled:
                timeoutWork.cancel()
            default:
                break
            }
        }
        conn.start(queue: queue)
    }

    private func handleIncomingPair(
        conn: NWConnection,
        payload: Data,
        timeoutWork: DispatchWorkItem,
        finish: @escaping () -> Void
    ) {
        guard let session = activePairing, session.expiresAt > Date(), session.failedAttempts < 5 else {
            writeJSONFrame(connection: conn, type: .pairError, value: WireErrorMsg(message: "对方未处于验证码配对状态，或验证码已过期。")) { _ in
                timeoutWork.cancel()
                finish()
            }
            return
        }

        guard let initMsg = try? JSONDecoder().decode(PairInitMsg.self, from: payload),
              let bSignPubData = Data(base64Encoded: initMsg.bSignPubB64),
              let bEphPubData = Data(base64Encoded: initMsg.bEphPubB64),
              let nonceB = Data(base64Encoded: initMsg.nonceBB64),
              let _ = try? Curve25519.Signing.PublicKey(rawRepresentation: bSignPubData),
              let bEphPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: bEphPubData),
              initMsg.bDeviceID != state.identity.deviceID
        else {
            writeJSONFrame(connection: conn, type: .pairError, value: WireErrorMsg(message: "配对请求格式无效。")) { _ in
                timeoutWork.cancel()
                finish()
            }
            return
        }

        let aSigningKey: Curve25519.Signing.PrivateKey
        do {
            aSigningKey = try state.identity.signingKey()
        } catch {
            timeoutWork.cancel()
            finish()
            return
        }

        let aSignPubData = aSigningKey.publicKey.rawRepresentation
        let aEphPriv = Curve25519.KeyAgreement.PrivateKey()
        let aEphPubData = aEphPriv.publicKey.rawRepresentation
        let nonceA = randomBytes(16)
        let salt = randomBytes(16)
        let aPort = actualPort > 0 ? actualPort : preferredPort

        let chal = PairChallengeMsg(
            aDeviceID: state.identity.deviceID,
            aDisplayName: state.identity.displayName,
            aSignPubB64: aSignPubData.base64EncodedString(),
            aEphPubB64: aEphPubData.base64EncodedString(),
            nonceAB64: nonceA.base64EncodedString(),
            saltB64: salt.base64EncodedString(),
            aListenPort: aPort
        )

        writeJSONFrame(connection: conn, type: .pairChallenge, value: chal) { [weak self] err in
            guard let self = self, err == nil else {
                timeoutWork.cancel()
                finish()
                return
            }

            readFrame(connection: conn) { proofResult in
                switch proofResult {
                case .failure:
                    timeoutWork.cancel()
                    finish()
                case .success(let (mType, proofData)):
                    guard mType == .pairProofB,
                          let proofMsg = try? JSONDecoder().decode(PairProofMsg.self, from: proofData),
                          let proofB = Data(base64Encoded: proofMsg.proofB64)
                    else {
                        timeoutWork.cancel()
                        finish()
                        return
                    }

                    guard var currentSession = self.activePairing,
                          currentSession.expiresAt > Date(),
                          currentSession.failedAttempts < 5
                    else {
                        writeJSONFrame(connection: conn, type: .pairError, value: WireErrorMsg(message: "验证码已失效，请重新生成。")) { _ in
                            timeoutWork.cancel()
                            finish()
                        }
                        return
                    }

                    do {
                        let shared = try aEphPriv.sharedSecretFromKeyAgreement(with: bEphPub)
                        let pwKey = try pbkdf2SHA256(code: currentSession.code, salt: salt)
                        let transcript = computePairTranscript(
                            aDeviceID: self.state.identity.deviceID,
                            bDeviceID: initMsg.bDeviceID,
                            aSignPub: aSignPubData,
                            bSignPub: bSignPubData,
                            aEphPub: aEphPubData,
                            bEphPub: bEphPubData,
                            nonceA: nonceA,
                            nonceB: nonceB,
                            salt: salt
                        )
                        let macKey = derivePairMacKey(sharedSecret: shared, pwKey: pwKey, salt: salt)

                        if !verifyPairProof(proofB, label: "PROOF-B", transcript: transcript, macKey: macKey) {
                            currentSession.failedAttempts += 1
                            if currentSession.failedAttempts >= 5 {
                                self.activePairing = nil
                                self.pairingTimer?.cancel()
                                self.pairingTimer = nil
                                self.syncListenerLocked()
                                self.notifyStateChanged()
                                writeJSONFrame(connection: conn, type: .pairError, value: WireErrorMsg(message: "验证码连续输错 5 次，已锁定失效，请在对方电脑重新生成。")) { _ in
                                    timeoutWork.cancel()
                                    finish()
                                }
                            } else {
                                self.activePairing = currentSession
                                let left = 5 - currentSession.failedAttempts
                                writeJSONFrame(connection: conn, type: .pairError, value: WireErrorMsg(message: "验证码不正确，还可再试 \(left) 次。")) { _ in
                                    timeoutWork.cancel()
                                    finish()
                                }
                            }
                            return
                        }

                        // One-time code consumed immediately on success
                        self.activePairing = nil
                        self.pairingTimer?.cancel()
                        self.pairingTimer = nil

                        let proofA = computePairProof(label: "PROOF-A", transcript: transcript, macKey: macKey)
                        let peerIP = extractIPString(from: conn.endpoint)
                        let newPeer = PairedPeer(
                            deviceID: initMsg.bDeviceID,
                            displayName: initMsg.bDisplayName,
                            ed25519PublicKeyB64: initMsg.bSignPubB64,
                            lastHost: peerIP,
                            lastPort: initMsg.bListenPort > 0 ? initMsg.bListenPort : LANCLIP_DEFAULT_PORT,
                            pairedAt: Date()
                        )
                        self.state.peer = newPeer
                        self.state.receiverEnabled = true
                        try saveState(self.state, to: self.stateURL)
                        self.syncListenerLocked()
                        self.notifyStateChanged()

                        writeJSONFrame(connection: conn, type: .pairProofA, value: PairProofMsg(proofB64: proofA.base64EncodedString())) { _ in
                            timeoutWork.cancel()
                            finish()
                            let cb = self.onPairingCompleted
                            DispatchQueue.main.async { cb?(newPeer) }
                        }
                    } catch {
                        timeoutWork.cancel()
                        finish()
                    }
                }
            }
        }
    }

    private func handleIncomingClip(
        conn: NWConnection,
        payload: Data,
        timeoutWork: DispatchWorkItem,
        finish: @escaping () -> Void
    ) {
        guard let peer = state.peer, state.receiverEnabled else {
            writeJSONFrame(connection: conn, type: .clipError, value: WireErrorMsg(message: "接收方未开启接收或未配对。")) { _ in
                timeoutWork.cancel()
                finish()
            }
            return
        }

        guard let initMsg = try? JSONDecoder().decode(ClipInitMsg.self, from: payload),
              initMsg.senderDeviceID == peer.deviceID,
              let ephPubAData = Data(base64Encoded: initMsg.ephPubAB64),
              let nonceA = Data(base64Encoded: initMsg.nonceAB64),
              let sigA = Data(base64Encoded: initMsg.sigAB64),
              let ephPubA = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPubAData),
              let peerSignPub = try? peer.publicKey()
        else {
            writeJSONFrame(connection: conn, type: .clipError, value: WireErrorMsg(message: "身份校验未通过。")) { _ in
                timeoutWork.cancel()
                finish()
            }
            return
        }

        let initSigned = clipInitSignData(
            senderID: peer.deviceID,
            receiverID: state.identity.deviceID,
            ephPubA: ephPubAData,
            nonceA: nonceA
        )
        guard peerSignPub.isValidSignature(sigA, for: initSigned) else {
            writeJSONFrame(connection: conn, type: .clipError, value: WireErrorMsg(message: "对方签名验证未通过，已拒绝连接。")) { _ in
                timeoutWork.cancel()
                finish()
            }
            return
        }

        let mySignKey: Curve25519.Signing.PrivateKey
        do {
            mySignKey = try state.identity.signingKey()
        } catch {
            timeoutWork.cancel()
            finish()
            return
        }

        let ephPrivB = Curve25519.KeyAgreement.PrivateKey()
        let ephPubBData = ephPrivB.publicKey.rawRepresentation
        let nonceB = randomBytes(16)
        let chalToSign = clipChallengeSignData(
            receiverID: state.identity.deviceID,
            senderID: peer.deviceID,
            ephPubA: ephPubAData,
            nonceA: nonceA,
            ephPubB: ephPubBData,
            nonceB: nonceB
        )
        guard let sigB = try? mySignKey.signature(for: chalToSign) else {
            timeoutWork.cancel()
            finish()
            return
        }

        let chalMsg = ClipChallengeMsg(
            ephPubBB64: ephPubBData.base64EncodedString(),
            nonceBB64: nonceB.base64EncodedString(),
            sigBB64: sigB.base64EncodedString()
        )

        writeJSONFrame(connection: conn, type: .clipChallenge, value: chalMsg) { [weak self] err in
            guard let self = self, err == nil else {
                timeoutWork.cancel()
                finish()
                return
            }

            readFrame(connection: conn) { payRes in
                switch payRes {
                case .failure:
                    timeoutWork.cancel()
                    finish()
                case .success(let (mType, payBody)):
                    guard mType == .clipPayload,
                          let sealedMsg = try? JSONDecoder().decode(ClipSealedMsg.self, from: payBody),
                          let combined = Data(base64Encoded: sealedMsg.combinedB64)
                    else {
                        timeoutWork.cancel()
                        finish()
                        return
                    }

                    do {
                        let shared = try ephPrivB.sharedSecretFromKeyAgreement(with: ephPubA)
                        let txHash = clipTranscriptHash(
                            senderID: peer.deviceID,
                            receiverID: self.state.identity.deviceID,
                            ephPubA: ephPubAData,
                            nonceA: nonceA,
                            ephPubB: ephPubBData,
                            nonceB: nonceB
                        )
                        let sessionKey = deriveClipSessionKey(sharedSecret: shared, transcriptHash: txHash)
                        let plain = try openClipData(combined, aadLabel: "PAYLOAD", transcriptHash: txHash, key: sessionKey)
                        guard plain.count <= LANCLIP_MAX_CLIP_BYTES,
                              let text = String(data: plain, encoding: .utf8)
                        else {
                            timeoutWork.cancel()
                            finish()
                            return
                        }

                        // Refresh peer IP if it changed via DHCP
                        let peerIP = extractIPString(from: conn.endpoint)
                        if !peerIP.isEmpty, var updatedPeer = self.state.peer, updatedPeer.lastHost != peerIP {
                            updatedPeer.lastHost = peerIP
                            self.state.peer = updatedPeer
                            try? saveState(self.state, to: self.stateURL)
                        }

                        let ackCombined = try sealClipData(Data("OK".utf8), aadLabel: "ACK", transcriptHash: txHash, key: sessionKey)
                        let ackMsg = ClipSealedMsg(combinedB64: ackCombined.base64EncodedString())
                        let cb = self.onTextReceived
                        let peerName = peer.displayName
                        DispatchQueue.main.async {
                            cb?(text, peerName)
                        }
                        writeJSONFrame(connection: conn, type: .clipAck, value: ackMsg) { _ in
                            timeoutWork.cancel()
                            finish()
                        }
                    } catch {
                        timeoutWork.cancel()
                        finish()
                    }
                }
            }
        }
    }

    // MARK: - Outgoing Pairing (Initiator Side)

    func pairWithEndpoint(
        endpoint: NWEndpoint?,
        fallbackHost: String,
        fallbackPort: UInt16,
        code: String,
        completion: @escaping (Result<PairedPeer, Error>) -> Void
    ) {
        let cleanCode = code.filter { $0.isNumber }
        guard cleanCode.count == 6 else {
            DispatchQueue.main.async {
                completion(.failure(ProtocolError.remoteError("请输入完整的 6 位数字验证码。")))
            }
            return
        }

        let targetEndpoint: NWEndpoint
        if let ep = endpoint {
            targetEndpoint = ep
        } else {
            let trimmedHost = fallbackHost.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !trimmedHost.isEmpty else {
                DispatchQueue.main.async {
                    completion(.failure(ProtocolError.remoteError("请先选择附近的 Mac，或填写对方局域网 IP。")))
                }
                return
            }
            let p = NWEndpoint.Port(rawValue: fallbackPort > 0 ? fallbackPort : LANCLIP_DEFAULT_PORT) ?? NWEndpoint.Port(integerLiteral: LANCLIP_DEFAULT_PORT)
            targetEndpoint = .hostPort(host: NWEndpoint.Host(trimmedHost), port: p)
        }

        queue.async {
            let myIdentity = self.state.identity
            let mySignKey: Curve25519.Signing.PrivateKey
            do {
                mySignKey = try myIdentity.signingKey()
            } catch {
                DispatchQueue.main.async { completion(.failure(error)) }
                return
            }

            let bSignPubData = mySignKey.publicKey.rawRepresentation
            let bEphPriv = Curve25519.KeyAgreement.PrivateKey()
            let bEphPubData = bEphPriv.publicKey.rawRepresentation
            let nonceB = randomBytes(16)
            let bPort = self.actualPort > 0 ? self.actualPort : self.preferredPort

            let params = NWParameters.tcp
            let conn = NWConnection(to: targetEndpoint, using: params)
            var done = false
            let finish = { (res: Result<PairedPeer, Error>) in
                guard !done else { return }
                done = true
                conn.cancel()
                DispatchQueue.main.async { completion(res) }
            }

            self.queue.asyncAfter(deadline: .now() + 8.0) {
                finish(.failure(ProtocolError.remoteError("连接超时：请确认另一台电脑已打开「局域网传文字」并正显示 6 位验证码。")))
            }

            conn.stateUpdateHandler = { [weak self] st in
                guard let self = self else { return }
                switch st {
                case .ready:
                    let initMsg = PairInitMsg(
                        bDeviceID: myIdentity.deviceID,
                        bDisplayName: myIdentity.displayName,
                        bSignPubB64: bSignPubData.base64EncodedString(),
                        bEphPubB64: bEphPubData.base64EncodedString(),
                        nonceBB64: nonceB.base64EncodedString(),
                        bListenPort: bPort
                    )
                    writeJSONFrame(connection: conn, type: .pairInit, value: initMsg) { err in
                        if let err = err {
                            finish(.failure(err))
                            return
                        }
                        readFrame(connection: conn) { chalRes in
                            switch chalRes {
                            case .failure(let err):
                                finish(.failure(err))
                            case .success(let (mType, chalBody)):
                                if mType == .pairError, let werr = try? JSONDecoder().decode(WireErrorMsg.self, from: chalBody) {
                                    finish(.failure(ProtocolError.remoteError(werr.message)))
                                    return
                                }
                                guard mType == .pairChallenge,
                                      let chal = try? JSONDecoder().decode(PairChallengeMsg.self, from: chalBody),
                                      let aSignPubData = Data(base64Encoded: chal.aSignPubB64),
                                      let aEphPubData = Data(base64Encoded: chal.aEphPubB64),
                                      let nonceA = Data(base64Encoded: chal.nonceAB64),
                                      let salt = Data(base64Encoded: chal.saltB64),
                                      let _ = try? Curve25519.Signing.PublicKey(rawRepresentation: aSignPubData),
                                      let aEphPub = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: aEphPubData)
                                else {
                                    finish(.failure(ProtocolError.cryptoFailure("对方返回了无效的配对响应。")))
                                    return
                                }

                                do {
                                    let shared = try bEphPriv.sharedSecretFromKeyAgreement(with: aEphPub)
                                    let pwKey = try pbkdf2SHA256(code: cleanCode, salt: salt)
                                    let transcript = computePairTranscript(
                                        aDeviceID: chal.aDeviceID,
                                        bDeviceID: myIdentity.deviceID,
                                        aSignPub: aSignPubData,
                                        bSignPub: bSignPubData,
                                        aEphPub: aEphPubData,
                                        bEphPub: bEphPubData,
                                        nonceA: nonceA,
                                        nonceB: nonceB,
                                        salt: salt
                                    )
                                    let macKey = derivePairMacKey(sharedSecret: shared, pwKey: pwKey, salt: salt)
                                    let proofB = computePairProof(label: "PROOF-B", transcript: transcript, macKey: macKey)

                                    writeJSONFrame(connection: conn, type: .pairProofB, value: PairProofMsg(proofB64: proofB.base64EncodedString())) { err2 in
                                        if let err2 = err2 {
                                            finish(.failure(err2))
                                            return
                                        }
                                        readFrame(connection: conn) { ackRes in
                                            switch ackRes {
                                            case .failure(let err):
                                                finish(.failure(err))
                                            case .success(let (ackType, ackBody)):
                                                if ackType == .pairError, let werr = try? JSONDecoder().decode(WireErrorMsg.self, from: ackBody) {
                                                    finish(.failure(ProtocolError.remoteError(werr.message)))
                                                    return
                                                }
                                                guard ackType == .pairProofA,
                                                      let proofAMsg = try? JSONDecoder().decode(PairProofMsg.self, from: ackBody),
                                                      let proofA = Data(base64Encoded: proofAMsg.proofB64),
                                                      verifyPairProof(proofA, label: "PROOF-A", transcript: transcript, macKey: macKey)
                                                else {
                                                    finish(.failure(ProtocolError.cryptoFailure("验证码校验未通过，请重新确认。")))
                                                    return
                                                }

                                                var peerHost = fallbackHost.trimmingCharacters(in: .whitespacesAndNewlines)
                                                if let remoteEp = conn.currentPath?.remoteEndpoint {
                                                    let resolvedIP = extractIPString(from: remoteEp)
                                                    if !resolvedIP.isEmpty {
                                                        peerHost = resolvedIP
                                                    }
                                                }
                                                let newPeer = PairedPeer(
                                                    deviceID: chal.aDeviceID,
                                                    displayName: chal.aDisplayName,
                                                    ed25519PublicKeyB64: chal.aSignPubB64,
                                                    lastHost: peerHost,
                                                    lastPort: chal.aListenPort > 0 ? chal.aListenPort : LANCLIP_DEFAULT_PORT,
                                                    pairedAt: Date()
                                                )
                                                do {
                                                    self.state.peer = newPeer
                                                    self.state.receiverEnabled = true
                                                    try saveState(self.state, to: self.stateURL)
                                                    self.syncListenerLocked()
                                                    self.notifyStateChanged()
                                                    finish(.success(newPeer))
                                                } catch {
                                                    finish(.failure(error))
                                                }
                                            }
                                        }
                                    }
                                } catch {
                                    finish(.failure(error))
                                }
                            }
                        }
                    }
                case .waiting(let nwErr):
                    if case .posix(let code) = nwErr, code == .ECONNREFUSED {
                        finish(.failure(ProtocolError.remoteError("对方拒绝了连接：请先在另一台电脑点击「生成 6 位配对验证码」。")))
                    }
                case .failed:
                    finish(.failure(ProtocolError.remoteError("无法连接到对方电脑，请确认两台 Mac 连在同一局域网。")))
                default:
                    break
                }
            }
            conn.start(queue: self.queue)
        }
    }

    // MARK: - Outgoing Clipboard Send

    func sendText(_ text: String, completion: @escaping (Result<(Int, String), Error>) -> Void) {
        guard let utf8 = text.data(using: .utf8), !utf8.isEmpty else {
            DispatchQueue.main.async {
                completion(.failure(ProtocolError.remoteError("当前剪贴板里没有可发送的文字。")))
            }
            return
        }
        guard utf8.count <= LANCLIP_MAX_CLIP_BYTES else {
            DispatchQueue.main.async {
                completion(.failure(ProtocolError.remoteError("剪贴板文字超过 1 MB 安全上限，已取消发送。")))
            }
            return
        }

        let charCount = text.count
        queue.async {
            guard let peer = self.state.peer else {
                DispatchQueue.main.async {
                    completion(.failure(ProtocolError.remoteError("尚未完成双机配对，请先用 6 位验证码配对。")))
                }
                return
            }

            if let hit = self.discovered.first(where: { $0.deviceID == peer.deviceID }) {
                self.attemptSend(endpoint: hit.endpoint, peer: peer, utf8: utf8, charCount: charCount, allowRediscovery: false, completion: completion)
            } else if !peer.lastHost.isEmpty {
                let p = NWEndpoint.Port(rawValue: peer.lastPort > 0 ? peer.lastPort : LANCLIP_DEFAULT_PORT) ?? NWEndpoint.Port(integerLiteral: LANCLIP_DEFAULT_PORT)
                let ep = NWEndpoint.hostPort(host: NWEndpoint.Host(peer.lastHost), port: p)
                self.attemptSend(endpoint: ep, peer: peer, utf8: utf8, charCount: charCount, allowRediscovery: self.advertiseBonjour, completion: completion)
            } else {
                self.rediscoverAndSend(peer: peer, utf8: utf8, charCount: charCount, completion: completion)
            }
        }
    }

    private func rediscoverAndSend(
        peer: PairedPeer,
        utf8: Data,
        charCount: Int,
        completion: @escaping (Result<(Int, String), Error>) -> Void
    ) {
        if !advertiseBonjour {
            DispatchQueue.main.async {
                completion(.failure(ProtocolError.remoteError("找不到对方电脑，请确认对方已打开软件并开启接收开关。")))
            }
            return
        }
        let params = NWParameters()
        let desc = NWBrowser.Descriptor.bonjourWithTXTRecord(type: LANCLIP_SERVICE_TYPE, domain: "local.")
        let tempBrowser = NWBrowser(for: desc, using: params)
        var finished = false

        let finishErr = { (msg: String) in
            guard !finished else { return }
            finished = true
            tempBrowser.cancel()
            DispatchQueue.main.async {
                completion(.failure(ProtocolError.remoteError(msg)))
            }
        }

        queue.asyncAfter(deadline: .now() + 2.5) {
            finishErr("找不到对方电脑：请确认两台 Mac 在同一局域网，且对方「局域网传文字」已打开接收。")
        }

        tempBrowser.browseResultsChangedHandler = { [weak self] results, _ in
            guard let self = self, !finished else { return }
            for r in results {
                if case let .bonjour(txt) = r.metadata,
                   case let .string(id) = txt.getEntry(for: "id"),
                   id == peer.deviceID {
                    finished = true
                    tempBrowser.cancel()
                    self.attemptSend(endpoint: r.endpoint, peer: peer, utf8: utf8, charCount: charCount, allowRediscovery: false, completion: completion)
                    return
                }
            }
        }
        tempBrowser.start(queue: queue)
    }

    private func attemptSend(
        endpoint: NWEndpoint,
        peer: PairedPeer,
        utf8: Data,
        charCount: Int,
        allowRediscovery: Bool,
        completion: @escaping (Result<(Int, String), Error>) -> Void
    ) {
        let myIdentity = state.identity
        let mySignKey: Curve25519.Signing.PrivateKey
        let peerSignPub: Curve25519.Signing.PublicKey
        do {
            mySignKey = try myIdentity.signingKey()
            peerSignPub = try peer.publicKey()
        } catch {
            DispatchQueue.main.async { completion(.failure(error)) }
            return
        }

        let ephPrivA = Curve25519.KeyAgreement.PrivateKey()
        let ephPubAData = ephPrivA.publicKey.rawRepresentation
        let nonceA = randomBytes(16)
        let initToSign = clipInitSignData(
            senderID: myIdentity.deviceID,
            receiverID: peer.deviceID,
            ephPubA: ephPubAData,
            nonceA: nonceA
        )
        let sigA: Data
        do {
            sigA = try mySignKey.signature(for: initToSign)
        } catch {
            DispatchQueue.main.async { completion(.failure(error)) }
            return
        }

        let conn = NWConnection(to: endpoint, using: NWParameters.tcp)
        var done = false

        let finish = { [weak self] (res: Result<(Int, String), Error>, retryBonjour: Bool) in
            guard !done else { return }
            done = true
            conn.cancel()
            if retryBonjour, let self = self {
                self.rediscoverAndSend(peer: peer, utf8: utf8, charCount: charCount, completion: completion)
            } else {
                DispatchQueue.main.async { completion(res) }
            }
        }

        queue.asyncAfter(deadline: .now() + 4.0) {
            finish(.failure(ProtocolError.remoteError("连接对方电脑超时，请确认两台 Mac 在同一局域网且对方接收已开启。")), allowRediscovery)
        }

        conn.stateUpdateHandler = { [weak self] st in
            guard let self = self else { return }
            switch st {
            case .ready:
                let initMsg = ClipInitMsg(
                    senderDeviceID: myIdentity.deviceID,
                    ephPubAB64: ephPubAData.base64EncodedString(),
                    nonceAB64: nonceA.base64EncodedString(),
                    sigAB64: sigA.base64EncodedString()
                )
                writeJSONFrame(connection: conn, type: .clipInit, value: initMsg) { err in
                    if let err = err {
                        finish(.failure(err), false)
                        return
                    }
                    readFrame(connection: conn) { chalRes in
                        switch chalRes {
                        case .failure(let err):
                            finish(.failure(err), false)
                        case .success(let (mType, chalBody)):
                            if mType == .clipError, let werr = try? JSONDecoder().decode(WireErrorMsg.self, from: chalBody) {
                                // Never retry on explicit crypto/pairing rejection
                                finish(.failure(ProtocolError.remoteError(werr.message)), false)
                                return
                            }
                            guard mType == .clipChallenge,
                                  let chal = try? JSONDecoder().decode(ClipChallengeMsg.self, from: chalBody),
                                  let ephPubBData = Data(base64Encoded: chal.ephPubBB64),
                                  let nonceB = Data(base64Encoded: chal.nonceBB64),
                                  let sigB = Data(base64Encoded: chal.sigBB64),
                                  let ephPubB = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: ephPubBData)
                            else {
                                finish(.failure(ProtocolError.cryptoFailure("安全拦截：对方电脑响应格式异常。")), false)
                                return
                            }

                            let expectedChalData = clipChallengeSignData(
                                receiverID: peer.deviceID,
                                senderID: myIdentity.deviceID,
                                ephPubA: ephPubAData,
                                nonceA: nonceA,
                                ephPubB: ephPubBData,
                                nonceB: nonceB
                            )
                            guard peerSignPub.isValidSignature(sigB, for: expectedChalData) else {
                                // NEVER fall back on signature failure
                                finish(.failure(ProtocolError.cryptoFailure("安全拦截：对方身份签名校验未通过，已中止发送。")), false)
                                return
                            }

                            do {
                                let shared = try ephPrivA.sharedSecretFromKeyAgreement(with: ephPubB)
                                let txHash = clipTranscriptHash(
                                    senderID: myIdentity.deviceID,
                                    receiverID: peer.deviceID,
                                    ephPubA: ephPubAData,
                                    nonceA: nonceA,
                                    ephPubB: ephPubBData,
                                    nonceB: nonceB
                                )
                                let sessionKey = deriveClipSessionKey(sharedSecret: shared, transcriptHash: txHash)
                                let combined = try sealClipData(utf8, aadLabel: "PAYLOAD", transcriptHash: txHash, key: sessionKey)
                                let payloadMsg = ClipSealedMsg(combinedB64: combined.base64EncodedString())

                                writeJSONFrame(connection: conn, type: .clipPayload, value: payloadMsg) { err2 in
                                    if let err2 = err2 {
                                        finish(.failure(err2), false)
                                        return
                                    }
                                    readFrame(connection: conn) { ackRes in
                                        switch ackRes {
                                        case .failure(let err):
                                            finish(.failure(err), false)
                                        case .success(let (ackType, ackBody)):
                                            guard ackType == .clipAck,
                                                  let ackSealed = try? JSONDecoder().decode(ClipSealedMsg.self, from: ackBody),
                                                  let ackBytes = Data(base64Encoded: ackSealed.combinedB64),
                                                  let ackPlain = try? openClipData(ackBytes, aadLabel: "ACK", transcriptHash: txHash, key: sessionKey),
                                                  ackPlain == Data("OK".utf8)
                                            else {
                                                finish(.failure(ProtocolError.cryptoFailure("未能确认对方已接收文字。")), false)
                                                return
                                            }

                                            if let remoteEp = conn.currentPath?.remoteEndpoint {
                                                let resolvedIP = extractIPString(from: remoteEp)
                                                if !resolvedIP.isEmpty, var updatedPeer = self.state.peer, updatedPeer.lastHost != resolvedIP {
                                                    updatedPeer.lastHost = resolvedIP
                                                    self.state.peer = updatedPeer
                                                    try? saveState(self.state, to: self.stateURL)
                                                }
                                            }
                                            finish(.success((charCount, peer.displayName)), false)
                                        }
                                    }
                                }
                            } catch {
                                finish(.failure(error), false)
                            }
                        }
                    }
                }
            case .waiting(let nwErr):
                if case .posix(let code) = nwErr, code == .ECONNREFUSED {
                    finish(.failure(ProtocolError.remoteError("无法连接对方电脑：请确认对方电脑已打开「局域网传文字」且接收开关处于开启状态。")), allowRediscovery)
                }
            case .failed:
                finish(.failure(ProtocolError.remoteError("无法连接对方电脑：请确认两台 Mac 在同一局域网且对方接收开关已开启。")), allowRediscovery)
            default:
                break
            }
        }
        conn.start(queue: queue)
    }
}
