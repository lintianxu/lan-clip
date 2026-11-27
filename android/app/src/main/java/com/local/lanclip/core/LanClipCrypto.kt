package com.local.lanclip.core

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.generators.PKCS5S2ParametersGenerator
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.KeyParameter
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.bouncycastle.crypto.signers.Ed25519Signer
import java.io.DataInputStream
import java.io.EOFException
import java.io.InputStream
import java.io.OutputStream
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.net.NetworkInterface
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

object LanClipCrypto {
    val MAGIC = byteArrayOf(0x4C, 0x43, 0x32, 0x01)
    const val DEFAULT_PORT = 47821
    const val MAX_CLIP_BYTES = 1_048_576
    const val MAX_FILE_BYTES = 4_294_967_296L
    const val FILE_CHUNK_SIZE = 262_144
    const val MAX_FRAME_BYTES = 1_100_000
    const val SERVICE_TYPE = "_lanclip._tcp."
    const val PBKDF2_ROUNDS = 100_000

    const val FILE_SEQ_META = 0L
    const val FILE_SEQ_READY = -3L // 0xFFFFFFFFFFFFFFFD unsigned
    const val FILE_SEQ_FINISH = -2L // 0xFFFFFFFFFFFFFFFE unsigned
    const val FILE_SEQ_ACK = -1L // 0xFFFFFFFFFFFFFFFF unsigned

    const val MSG_PAIR_INIT: Byte = 0x01
    const val MSG_PAIR_CHALLENGE: Byte = 0x02
    const val MSG_PAIR_PROOF_B: Byte = 0x03
    const val MSG_PAIR_PROOF_A: Byte = 0x04
    const val MSG_PAIR_ERROR: Byte = 0x0F

    const val MSG_CLIP_INIT: Byte = 0x11
    const val MSG_CLIP_CHALLENGE: Byte = 0x12
    const val MSG_CLIP_PAYLOAD: Byte = 0x13
    const val MSG_CLIP_ACK: Byte = 0x14
    const val MSG_CLIP_ERROR: Byte = 0x1F

    const val MSG_FILE_INIT: Byte = 0x21
    const val MSG_FILE_CHALLENGE: Byte = 0x22
    const val MSG_FILE_META: Byte = 0x23
    const val MSG_FILE_READY: Byte = 0x24
    const val MSG_FILE_CHUNK: Byte = 0x25
    const val MSG_FILE_FINISH: Byte = 0x26
    const val MSG_FILE_ACK: Byte = 0x27
    const val MSG_FILE_ERROR: Byte = 0x2F

    private val rng = SecureRandom()

    private val WINDOWS_RESERVED = setOf(
        "CON", "PRN", "AUX", "NUL",
        "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
        "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9"
    )

    fun b64Encode(data: ByteArray): String = Base64.getEncoder().encodeToString(data)

    fun b64Decode(str: String): ByteArray = Base64.getDecoder().decode(str)

    fun randomBytes(n: Int): ByteArray = ByteArray(n).also { rng.nextBytes(it) }

    fun randomSixDigitCode(): String = String.format("%06d", rng.nextInt(1_000_000))

    fun generateEd25519Keypair(): Pair<ByteArray, ByteArray> {
        val priv = Ed25519PrivateKeyParameters(rng)
        val pub = priv.generatePublicKey()
        return priv.encoded to pub.encoded
    }

    fun ed25519PubFromSeed(seed32: ByteArray): ByteArray {
        return Ed25519PrivateKeyParameters(seed32, 0).generatePublicKey().encoded
    }

    fun ed25519Sign(seed32: ByteArray, msg: ByteArray): ByteArray {
        val priv = Ed25519PrivateKeyParameters(seed32, 0)
        val signer = Ed25519Signer()
        signer.init(true, priv)
        signer.update(msg, 0, msg.size)
        return signer.generateSignature()
    }

    fun ed25519Verify(pub32: ByteArray, msg: ByteArray, sig64: ByteArray): Boolean {
        return try {
            val pub = Ed25519PublicKeyParameters(pub32, 0)
            val verifier = Ed25519Signer()
            verifier.init(false, pub)
            verifier.update(msg, 0, msg.size)
            verifier.verifySignature(sig64)
        } catch (_: Exception) {
            false
        }
    }

    fun generateX25519Keypair(): Pair<ByteArray, ByteArray> {
        val priv = X25519PrivateKeyParameters(rng)
        val pub = priv.generatePublicKey()
        return priv.encoded to pub.encoded
    }

    fun x25519Shared(priv32: ByteArray, pub32: ByteArray): ByteArray {
        val priv = X25519PrivateKeyParameters(priv32, 0)
        val pub = X25519PublicKeyParameters(pub32, 0)
        val agree = X25519Agreement()
        agree.init(priv)
        return ByteArray(32).also { agree.calculateAgreement(pub, it, 0) }
    }

    fun pbkdf2Sha256(code: String, salt: ByteArray, rounds: Int = PBKDF2_ROUNDS): ByteArray {
        val gen = PKCS5S2ParametersGenerator(SHA256Digest())
        gen.init(code.toByteArray(Charsets.UTF_8), salt, rounds)
        return (gen.generateDerivedParameters(256) as KeyParameter).key
    }

    fun hkdfSha256(ikm: ByteArray, salt: ByteArray, info: ByteArray, outLen: Int): ByteArray {
        val hkdf = HKDFBytesGenerator(SHA256Digest())
        hkdf.init(HKDFParameters(ikm, salt, info))
        return ByteArray(outLen).also { hkdf.generateBytes(it, 0, outLen) }
    }

    fun sha256(vararg parts: ByteArray): ByteArray {
        val md = MessageDigest.getInstance("SHA-256")
        for (p in parts) md.update(p)
        return md.digest()
    }

    fun hmacSha256(key: ByteArray, vararg parts: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        for (p in parts) mac.update(p)
        return mac.doFinal()
    }

    fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

    fun constantTimeEqualHex(a: String, b: String): Boolean {
        val la = a.lowercase().toByteArray(Charsets.UTF_8)
        val lb = b.lowercase().toByteArray(Charsets.UTF_8)
        return la.isNotEmpty() && MessageDigest.isEqual(la, lb)
    }

    // Pairing crypto
    fun computePairTranscript(
        aDeviceID: String, bDeviceID: String,
        aSignPub: ByteArray, bSignPub: ByteArray,
        aEphPub: ByteArray, bEphPub: ByteArray,
        nonceA: ByteArray, nonceB: ByteArray, salt: ByteArray
    ): ByteArray = sha256(
        "LANCLIP-PAIR-v2".toByteArray(Charsets.UTF_8),
        aDeviceID.toByteArray(Charsets.UTF_8),
        "|".toByteArray(Charsets.UTF_8),
        bDeviceID.toByteArray(Charsets.UTF_8),
        aSignPub, bSignPub, aEphPub, bEphPub, nonceA, nonceB, salt
    )

    fun derivePairMacKey(sharedSecret: ByteArray, pwKey: ByteArray, salt: ByteArray): ByteArray {
        val ikm = sharedSecret + pwKey
        return hkdfSha256(ikm, salt, "lanclip-pair-mac-v2".toByteArray(Charsets.UTF_8), 32)
    }

    fun computePairProof(label: String, transcript: ByteArray, macKey: ByteArray): ByteArray {
        return hmacSha256(macKey, label.toByteArray(Charsets.UTF_8), transcript)
    }

    fun verifyPairProof(proof: ByteArray, label: String, transcript: ByteArray, macKey: ByteArray): Boolean {
        return constantTimeEquals(proof, computePairProof(label, transcript, macKey))
    }

    // Clipboard crypto
    fun clipInitSignData(senderID: String, receiverID: String, ephPubA: ByteArray, nonceA: ByteArray): ByteArray {
        return "LANCLIP-CLIP-INIT-v2".toByteArray(Charsets.UTF_8) +
            senderID.toByteArray(Charsets.UTF_8) +
            "|".toByteArray(Charsets.UTF_8) +
            receiverID.toByteArray(Charsets.UTF_8) + ephPubA + nonceA
    }

    fun clipChallengeSignData(
        receiverID: String, senderID: String,
        ephPubA: ByteArray, nonceA: ByteArray,
        ephPubB: ByteArray, nonceB: ByteArray
    ): ByteArray {
        return "LANCLIP-CLIP-CHAL-v2".toByteArray(Charsets.UTF_8) +
            receiverID.toByteArray(Charsets.UTF_8) +
            "|".toByteArray(Charsets.UTF_8) +
            senderID.toByteArray(Charsets.UTF_8) + ephPubA + nonceA + ephPubB + nonceB
    }

    fun clipTranscriptHash(
        senderID: String, receiverID: String,
        ephPubA: ByteArray, nonceA: ByteArray,
        ephPubB: ByteArray, nonceB: ByteArray
    ): ByteArray = sha256(
        "LANCLIP-CLIP-TX-v2".toByteArray(Charsets.UTF_8),
        senderID.toByteArray(Charsets.UTF_8),
        "|".toByteArray(Charsets.UTF_8),
        receiverID.toByteArray(Charsets.UTF_8),
        ephPubA, nonceA, ephPubB, nonceB
    )

    fun deriveClipSessionKey(sharedSecret: ByteArray, transcriptHash: ByteArray): ByteArray {
        return hkdfSha256(sharedSecret, transcriptHash, "lanclip-aes-gcm-v2".toByteArray(Charsets.UTF_8), 32)
    }

    fun sealClipData(plain: ByteArray, aadLabel: String, transcriptHash: ByteArray, key: ByteArray): ByteArray {
        val nonce = randomBytes(12)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aadLabel.toByteArray(Charsets.UTF_8) + transcriptHash)
        val ctAndTag = cipher.doFinal(plain)
        return nonce + ctAndTag
    }

    fun openClipData(combined: ByteArray, aadLabel: String, transcriptHash: ByteArray, key: ByteArray): ByteArray {
        require(combined.size >= 28) { "密文格式无效" }
        val nonce = combined.copyOfRange(0, 12)
        val ctAndTag = combined.copyOfRange(12, combined.size)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aadLabel.toByteArray(Charsets.UTF_8) + transcriptHash)
        return cipher.doFinal(ctAndTag)
    }

    // Streaming file crypto
    fun fileInitSignData(senderID: String, receiverID: String, ephPubA: ByteArray, nonceA: ByteArray): ByteArray {
        return "LANCLIP-FILE-INIT-v3".toByteArray(Charsets.UTF_8) +
            senderID.toByteArray(Charsets.UTF_8) +
            "|".toByteArray(Charsets.UTF_8) +
            receiverID.toByteArray(Charsets.UTF_8) + ephPubA + nonceA
    }

    fun fileChallengeSignData(
        receiverID: String, senderID: String,
        ephPubA: ByteArray, nonceA: ByteArray,
        ephPubB: ByteArray, nonceB: ByteArray
    ): ByteArray {
        return "LANCLIP-FILE-CHAL-v3".toByteArray(Charsets.UTF_8) +
            receiverID.toByteArray(Charsets.UTF_8) +
            "|".toByteArray(Charsets.UTF_8) +
            senderID.toByteArray(Charsets.UTF_8) + ephPubA + nonceA + ephPubB + nonceB
    }

    fun fileTranscriptHash(
        senderID: String, receiverID: String,
        ephPubA: ByteArray, nonceA: ByteArray,
        ephPubB: ByteArray, nonceB: ByteArray
    ): ByteArray = sha256(
        "LANCLIP-FILE-TX-v3".toByteArray(Charsets.UTF_8),
        senderID.toByteArray(Charsets.UTF_8),
        "|".toByteArray(Charsets.UTF_8),
        receiverID.toByteArray(Charsets.UTF_8),
        ephPubA, nonceA, ephPubB, nonceB
    )

    fun deriveFileSessionKeys(sharedSecret: ByteArray, transcriptHash: ByteArray): Pair<ByteArray, ByteArray> {
        val key = hkdfSha256(sharedSecret, transcriptHash, "lanclip-file-gcm-v3".toByteArray(Charsets.UTF_8), 32)
        val nonceBase = hkdfSha256(sharedSecret, transcriptHash, "lanclip-file-nonce-v3".toByteArray(Charsets.UTF_8), 12)
        return key to nonceBase
    }

    fun uint64BE(v: Long): ByteArray = ByteBuffer.allocate(8).order(ByteOrder.BIG_ENDIAN).putLong(v).array()

    fun fileDeterministicNonce(nonceBase: ByteArray, seq: Long): ByteArray {
        require(nonceBase.size == 12) { "无效的 nonce 基准长度" }
        val tailVal = ByteBuffer.wrap(nonceBase, 4, 8).order(ByteOrder.BIG_ENDIAN).long
        val xored = uint64BE(tailVal xor seq)
        return nonceBase.copyOfRange(0, 4) + xored
    }

    fun fileAAD(label: String, seqPrefix: Long?, transcriptHash: ByteArray): ByteArray {
        val base = label.toByteArray(Charsets.UTF_8)
        return if (seqPrefix != null) {
            base + uint64BE(seqPrefix) + transcriptHash
        } else {
            base + transcriptHash
        }
    }

    fun sealFileRaw(plain: ByteArray, key: ByteArray, nonceBase: ByteArray, seq: Long, aad: ByteArray): ByteArray {
        val nonce = fileDeterministicNonce(nonceBase, seq)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(plain)
    }

    fun openFileRaw(cipherAndTag: ByteArray, key: ByteArray, nonceBase: ByteArray, seq: Long, aad: ByteArray): ByteArray {
        require(cipherAndTag.size >= 16) { "文件密文格式无效" }
        val nonce = fileDeterministicNonce(nonceBase, seq)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(aad)
        return cipher.doFinal(cipherAndTag)
    }

    // Wire framing
    fun writeFrame(out: OutputStream, msgType: Byte, payload: ByteArray) {
        require(payload.size <= MAX_FRAME_BYTES) { "数据包超出安全大小上限" }
        val hdr = ByteBuffer.allocate(9).order(ByteOrder.BIG_ENDIAN)
        hdr.put(MAGIC)
        hdr.put(msgType)
        hdr.putInt(payload.size)
        out.write(hdr.array())
        if (payload.isNotEmpty()) out.write(payload)
        out.flush()
    }

    fun readFrame(input: InputStream): Pair<Byte, ByteArray> {
        val dis = DataInputStream(input)
        val hdr = ByteArray(9)
        try {
            dis.readFully(hdr)
        } catch (e: EOFException) {
            throw IllegalStateException("对方提前断开了连接", e)
        }
        for (i in 0..3) {
            if (hdr[i] != MAGIC[i]) throw IllegalStateException("收到无效的数据包头")
        }
        val msgType = hdr[4]
        val len = ByteBuffer.wrap(hdr, 5, 4).order(ByteOrder.BIG_ENDIAN).int.toLong() and 0xFFFFFFFFL
        if (len > MAX_FRAME_BYTES) throw IllegalStateException("数据包超出安全大小上限")
        val body = ByteArray(len.toInt())
        if (len > 0) dis.readFully(body)
        return msgType to body
    }

    // Filename sanitization
    fun sanitizeReceivedFileName(raw: String): String {
        val parts = raw.split('/', '\\').filter { it.isNotEmpty() }
        var base = parts.lastOrNull() ?: ""
        val forbidden = setOf('<', '>', ':', '"', '/', '\\', '|', '?', '*')
        val sb = StringBuilder()
        for (ch in base) {
            val code = ch.code
            if (code < 0x20 || code == 0x7F || ch in forbidden) continue
            sb.append(ch)
        }
        base = sb.toString().trimStart('.', ' ').trimEnd('.', ' ')
        if (base.isEmpty() || base == "." || base == "..") return "received_file"
        val stem = base.substringBefore('.')
        if (stem.uppercase() in WINDOWS_RESERVED) return "received_file"
        val utf8Bytes = base.toByteArray(Charsets.UTF_8)
        if (utf8Bytes.size > 180) {
            val out = StringBuilder()
            var count = 0
            var i = 0
            while (i < base.length) {
                val cp = base.codePointAt(i)
                val str = String(Character.toChars(cp))
                val len = str.toByteArray(Charsets.UTF_8).size
                if (count + len > 180) break
                out.append(str)
                count += len
                i += Character.charCount(cp)
            }
            base = out.toString().trimEnd('.', ' ')
            if (base.isEmpty()) return "received_file"
        }
        return base
    }

    // LAN IP Allowlist
    fun isAllowedIPv4Bytes(a: Int, b: Int, c: Int, d: Int): Boolean {
        if (a == 198 && (b == 18 || b == 19)) return false
        if (a == 10) return true
        if (a == 172 && b in 16..31) return true
        if (a == 192 && b == 168) return true
        if (a == 127) return true
        if (a == 169 && b == 254) return true
        return false
    }

    fun isAllowedAddress(addr: InetAddress?): Boolean {
        if (addr == null) return false
        if (addr is Inet4Address) {
            val b = addr.address
            return isAllowedIPv4Bytes(b[0].toInt() and 0xFF, b[1].toInt() and 0xFF, b[2].toInt() and 0xFF, b[3].toInt() and 0xFF)
        }
        if (addr is Inet6Address) {
            if (addr.isLoopbackAddress) return true
            val b = addr.address
            val b0 = b[0].toInt() and 0xFF
            val b1 = b[1].toInt() and 0xFF
            if (b0 == 0xFE && (b1 and 0xC0) == 0x80) return true
            if ((b0 and 0xFE) == 0xFC) return true
            return false
        }
        return false
    }

    fun detectLocalLANIP(): String {
        return try {
            val ifaces = NetworkInterface.getNetworkInterfaces() ?: return ""
            for (ifc in ifaces) {
                if (!ifc.isUp || ifc.isLoopback) continue
                val addrs = ifc.inetAddresses
                while (addrs.hasMoreElements()) {
                    val a = addrs.nextElement()
                    if (a is Inet4Address && !a.isLoopbackAddress && !a.isLinkLocalAddress && isAllowedAddress(a)) {
                        return a.hostAddress ?: ""
                    }
                }
            }
            ""
        } catch (_: Exception) {
            ""
        }
    }

    fun bytesToHex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }

    fun hexToBytes(hex: String): ByteArray {
        val len = hex.length
        val out = ByteArray(len / 2)
        for (i in 0 until len step 2) {
            out[i / 2] = hex.substring(i, i + 2).toInt(16).toByte()
        }
        return out
    }
}
