import Foundation
import CryptoKit

func toHex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
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

@main
struct GenVectorsMain {
    static func main() throws {
        let outPath = CommandLine.arguments.count >= 2
            ? CommandLine.arguments[1]
            : "protocol/test_vectors.json"

        // Deterministic private keys / nonces / salts for cross-platform vector verification
        let signPrivBytes = Data((0..<32).map { UInt8(($0 * 7 + 11) & 0xff) })
        let signPriv = try Curve25519.Signing.PrivateKey(rawRepresentation: signPrivBytes)
        let signPub = signPriv.publicKey.rawRepresentation
        let signMsg = Data("LANCLIP-ED25519-VECTOR-v3".utf8)
        let signSig = try signPriv.signature(for: signMsg)

        // Pairing vector
        let aDeviceID = "1122334455667788"
        let bDeviceID = "99aabbccddeeff00"
        let aSignPub = Data((0..<32).map { UInt8(($0 + 0x10) & 0xff) })
        let bSignPub = Data((0..<32).map { UInt8(($0 + 0x40) & 0xff) })

        let aEphPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data((0..<32).map { UInt8(($0 + 0x20) & 0xff) }))
        let bEphPriv = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data((0..<32).map { UInt8(($0 + 0x50) & 0xff) }))
        let aEphPub = aEphPriv.publicKey.rawRepresentation
        let bEphPub = bEphPriv.publicKey.rawRepresentation
        let nonceA = Data((0..<16).map { UInt8(($0 + 0x70) & 0xff) })
        let nonceB = Data((0..<16).map { UInt8(($0 + 0x80) & 0xff) })
        let salt = Data((0..<16).map { UInt8(($0 + 0x90) & 0xff) })
        let code = "482916"

        let pairShared = try aEphPriv.sharedSecretFromKeyAgreement(with: bEphPriv.publicKey)
        let pwKey = try pbkdf2SHA256(code: code, salt: salt)
        let pairTx = computePairTranscript(
            aDeviceID: aDeviceID, bDeviceID: bDeviceID,
            aSignPub: aSignPub, bSignPub: bSignPub,
            aEphPub: aEphPub, bEphPub: bEphPub,
            nonceA: nonceA, nonceB: nonceB, salt: salt
        )
        let macKey = derivePairMacKey(sharedSecret: pairShared, pwKey: pwKey, salt: salt)
        let proofB = computePairProof(label: "PROOF-B", transcript: pairTx, macKey: macKey)
        let proofA = computePairProof(label: "PROOF-A", transcript: pairTx, macKey: macKey)

        // Clipboard vector
        let clipInitSigned = clipInitSignData(senderID: aDeviceID, receiverID: bDeviceID, ephPubA: aEphPub, nonceA: nonceA)
        let clipChalSigned = clipChallengeSignData(receiverID: bDeviceID, senderID: aDeviceID, ephPubA: aEphPub, nonceA: nonceA, ephPubB: bEphPub, nonceB: nonceB)
        let clipTx = clipTranscriptHash(senderID: aDeviceID, receiverID: bDeviceID, ephPubA: aEphPub, nonceA: nonceA, ephPubB: bEphPub, nonceB: nonceB)
        let clipKey = deriveClipSessionKey(sharedSecret: pairShared, transcriptHash: clipTx)
        let clipPlain = Data("Hello 局域网快传 🔐🚀".utf8)
        let clipCombined = try sealClipData(clipPlain, aadLabel: "PAYLOAD", transcriptHash: clipTx, key: clipKey)
        let clipAckCombined = try sealClipData(Data("OK".utf8), aadLabel: "ACK", transcriptHash: clipTx, key: clipKey)

        // File transfer vector
        let fileInitSigned = fileInitSignData(senderID: aDeviceID, receiverID: bDeviceID, ephPubA: aEphPub, nonceA: nonceA)
        let fileChalSigned = fileChallengeSignData(receiverID: bDeviceID, senderID: aDeviceID, ephPubA: aEphPub, nonceA: nonceA, ephPubB: bEphPub, nonceB: nonceB)
        let fileTx = fileTranscriptHash(senderID: aDeviceID, receiverID: bDeviceID, ephPubA: aEphPub, nonceA: nonceA, ephPubB: bEphPub, nonceB: nonceB)
        let (fileKey, nonceBase) = deriveFileSessionKeys(sharedSecret: pairShared, transcriptHash: fileTx)

        let metaPlain = Data(#"{"chunkSize":262144,"fileName":"测试文档.txt","fileSize":19}"#.utf8)
        let metaCipher = try sealFileRaw(plain: metaPlain, key: fileKey, nonceBase: nonceBase, seq: FILE_SEQ_META, aad: fileAAD(label: "FILE-META", transcriptHash: fileTx))

        let readyPlain = Data("OK".utf8)
        let readyCipher = try sealFileRaw(plain: readyPlain, key: fileKey, nonceBase: nonceBase, seq: FILE_SEQ_READY, aad: fileAAD(label: "FILE-READY", transcriptHash: fileTx))

        let chunk1Plain = Data("第一段加密文件内容-".utf8)
        let chunk1Cipher = try sealFileRaw(plain: chunk1Plain, key: fileKey, nonceBase: nonceBase, seq: 1, aad: fileAAD(label: "FILE-CHUNK", seqPrefix: 1, transcriptHash: fileTx))

        let chunk2Plain = Data("Chunk2-🚀".utf8)
        let chunk2Cipher = try sealFileRaw(plain: chunk2Plain, key: fileKey, nonceBase: nonceBase, seq: 2, aad: fileAAD(label: "FILE-CHUNK", seqPrefix: 2, transcriptHash: fileTx))

        let finishPlain = Data(#"{"sha256Hex":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","totalChunks":2}"#.utf8)
        let finishCipher = try sealFileRaw(plain: finishPlain, key: fileKey, nonceBase: nonceBase, seq: FILE_SEQ_FINISH, aad: fileAAD(label: "FILE-FINISH", transcriptHash: fileTx))

        let ackPlain = Data(#"{"savedName":"测试文档.txt"}"#.utf8)
        let ackCipher = try sealFileRaw(plain: ackPlain, key: fileKey, nonceBase: nonceBase, seq: FILE_SEQ_ACK, aad: fileAAD(label: "FILE-ACK", transcriptHash: fileTx))

        let root: [String: Any] = [
            "ed25519": [
                "privHex": toHex(signPriv.rawRepresentation),
                "pubHex": toHex(signPub),
                "msgHex": toHex(signMsg),
                "sigHex": toHex(signSig)
            ],
            "pairing": [
                "aDeviceID": aDeviceID,
                "bDeviceID": bDeviceID,
                "aSignPubHex": toHex(aSignPub),
                "bSignPubHex": toHex(bSignPub),
                "aEphPrivHex": toHex(aEphPriv.rawRepresentation),
                "aEphPubHex": toHex(aEphPub),
                "bEphPrivHex": toHex(bEphPriv.rawRepresentation),
                "bEphPubHex": toHex(bEphPub),
                "nonceAHex": toHex(nonceA),
                "nonceBHex": toHex(nonceB),
                "saltHex": toHex(salt),
                "code": code,
                "sharedSecretHex": toHex(pairShared.withUnsafeBytes { Data($0) }),
                "pwKeyHex": toHex(pwKey),
                "transcriptHex": toHex(pairTx),
                "macKeyHex": toHex(macKey.withUnsafeBytes { Data($0) }),
                "proofBHex": toHex(proofB),
                "proofAHex": toHex(proofA)
            ],
            "clipboard": [
                "senderID": aDeviceID,
                "receiverID": bDeviceID,
                "ephPrivAHex": toHex(aEphPriv.rawRepresentation),
                "ephPubAHex": toHex(aEphPub),
                "ephPrivBHex": toHex(bEphPriv.rawRepresentation),
                "ephPubBHex": toHex(bEphPub),
                "nonceAHex": toHex(nonceA),
                "nonceBHex": toHex(nonceB),
                "initSignDataHex": toHex(clipInitSigned),
                "chalSignDataHex": toHex(clipChalSigned),
                "txHashHex": toHex(clipTx),
                "sessionKeyHex": toHex(clipKey.withUnsafeBytes { Data($0) }),
                "plainHex": toHex(clipPlain),
                "combinedB64": clipCombined.base64EncodedString(),
                "ackCombinedB64": clipAckCombined.base64EncodedString()
            ],
            "file": [
                "senderID": aDeviceID,
                "receiverID": bDeviceID,
                "ephPrivAHex": toHex(aEphPriv.rawRepresentation),
                "ephPubAHex": toHex(aEphPub),
                "ephPrivBHex": toHex(bEphPriv.rawRepresentation),
                "ephPubBHex": toHex(bEphPub),
                "nonceAHex": toHex(nonceA),
                "nonceBHex": toHex(nonceB),
                "initSignDataHex": toHex(fileInitSigned),
                "chalSignDataHex": toHex(fileChalSigned),
                "txHashHex": toHex(fileTx),
                "sessionKeyHex": toHex(fileKey.withUnsafeBytes { Data($0) }),
                "nonceBaseHex": toHex(nonceBase),
                "metaSeq": String(FILE_SEQ_META),
                "metaPlainHex": toHex(metaPlain),
                "metaCipherHex": toHex(metaCipher),
                "readySeq": String(FILE_SEQ_READY),
                "readyPlainHex": toHex(readyPlain),
                "readyCipherHex": toHex(readyCipher),
                "chunk1Seq": "1",
                "chunk1PlainHex": toHex(chunk1Plain),
                "chunk1CipherHex": toHex(chunk1Cipher),
                "chunk2Seq": "2",
                "chunk2PlainHex": toHex(chunk2Plain),
                "chunk2CipherHex": toHex(chunk2Cipher),
                "finishSeq": String(FILE_SEQ_FINISH),
                "finishPlainHex": toHex(finishPlain),
                "finishCipherHex": toHex(finishCipher),
                "ackSeq": String(FILE_SEQ_ACK),
                "ackPlainHex": toHex(ackPlain),
                "ackCipherHex": toHex(ackCipher)
            ]
        ]

        let jsonData = try JSONSerialization.data(withJSONObject: root, options: [.prettyPrinted, .sortedKeys])
        let outURL = URL(fileURLWithPath: outPath)
        try FileManager.default.createDirectory(at: outURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try jsonData.write(to: outURL)
        print("Generated \(outPath)")
    }
}
