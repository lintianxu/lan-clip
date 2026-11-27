package com.local.lanclip.core

import org.json.JSONObject
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.net.InetSocketAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.security.MessageDigest
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.ScheduledFuture
import java.util.concurrent.Semaphore
import java.util.concurrent.TimeUnit

data class DiscoveredDevice(
    val deviceID: String,
    val displayName: String,
    val isPairing: Boolean,
    val host: String,
    val port: Int
)

interface FileWriteSession {
    fun write(bytes: ByteArray, length: Int)
    fun commit(): String // returns final saved display name
    fun abort()
}

interface FileReceiveSink {
    fun openSession(sanitizedName: String, expectedSize: Long): FileWriteSession
}

class DirectoryFileReceiveSink(private val dir: File) : FileReceiveSink {
    override fun openSession(sanitizedName: String, expectedSize: Long): FileWriteSession {
        if (!dir.exists()) dir.mkdirs()
        val part = File(dir, ".part.${System.nanoTime()}")
        val fos = FileOutputStream(part)
        return object : FileWriteSession {
            override fun write(bytes: ByteArray, length: Int) {
                fos.write(bytes, 0, length)
            }

            override fun commit(): String {
                fos.fd.sync()
                fos.close()
                val dest = uniqueFile(dir, sanitizedName)
                if (!part.renameTo(dest)) {
                    part.copyTo(dest, overwrite = false)
                    part.delete()
                }
                return dest.name
            }

            override fun abort() {
                try { fos.close() } catch (_: Exception) {}
                part.delete()
            }
        }
    }

    private fun uniqueFile(dir: File, sanitizedName: String): File {
        val first = File(dir, sanitizedName)
        if (!first.exists()) return first
        val dot = sanitizedName.lastIndexOf('.')
        val stem = if (dot > 0) sanitizedName.substring(0, dot) else sanitizedName
        val ext = if (dot > 0) sanitizedName.substring(dot) else ""
        var i = 1
        while (true) {
            val cand = File(dir, "$stem ($i)$ext")
            if (!cand.exists()) return cand
            i++
        }
    }
}

private class PairingSession(
    val code: String,
    val expiresAtMs: Long,
    var failedAttempts: Int = 0,
    var expireFuture: ScheduledFuture<*>? = null
)

class LanClipEngine(
    private val store: StateStore,
    private val fileSink: FileReceiveSink,
    private val preferredPort: Int = LanClipCrypto.DEFAULT_PORT,
    private val advertiseHook: ((active: Boolean, port: Int, pairing: Boolean, id: String, name: String) -> Unit)? = null
) {
    private val lock = Any()
    private var state: PersistedState = store.loadOrCreate()
    private var serverSocket: ServerSocket? = null
    @Volatile
    private var actualPort: Int = 0
    private var closed = false
    private var activePairing: PairingSession? = null

    private val sem = Semaphore(4)
    private val ioPool = Executors.newCachedThreadPool()
    private val scheduler: ScheduledExecutorService = Executors.newSingleThreadScheduledExecutor()

    private val discoveredMap = LinkedHashMap<String, DiscoveredDevice>()

    var onStateChanged: (() -> Unit)? = null
    var onPairingCompleted: ((PairedPeer) -> Unit)? = null
    var onPairingExpired: (() -> Unit)? = null
    var onTextReceived: ((text: String, peerName: String) -> Unit)? = null
    var onFileReceived: ((savedName: String, peerName: String) -> Unit)? = null

    fun currentIdentity(): DeviceIdentity = synchronized(lock) { state.identity }

    fun pairedPeers(): List<PairedPeer> = synchronized(lock) { state.peers.toList() }

    fun activePeer(): PairedPeer? = synchronized(lock) { activePeerLocked() }

    private fun activePeerLocked(): PairedPeer? {
        val aid = state.activePeerID
        return state.peers.firstOrNull { it.deviceID == aid } ?: state.peers.firstOrNull()
    }

    private fun findPeerLocked(id: String): PairedPeer? = state.peers.firstOrNull { it.deviceID == id }

    private fun upsertPeerLocked(peer: PairedPeer) {
        val idx = state.peers.indexOfFirst { it.deviceID == peer.deviceID }
        if (idx >= 0) state.peers[idx] = peer else state.peers.add(peer)
        state.activePeerID = peer.deviceID
    }

    fun setActivePeer(id: String) {
        synchronized(lock) {
            if (state.peers.any { it.deviceID == id }) {
                state.activePeerID = id
                store.save(state)
            }
        }
        onStateChanged?.invoke()
    }

    fun removePeer(id: String) {
        synchronized(lock) {
            state.peers.removeAll { it.deviceID == id }
            if (state.activePeerID == id) {
                state.activePeerID = state.peers.firstOrNull()?.deviceID
            }
            if (state.peers.isEmpty()) {
                state.receiverEnabled = true
            }
            store.save(state)
            syncListenerLocked()
        }
        onStateChanged?.invoke()
    }

    fun clearPairing() {
        synchronized(lock) {
            state.peers.clear()
            state.activePeerID = null
            state.receiverEnabled = true
            store.save(state)
            syncListenerLocked()
        }
        onStateChanged?.invoke()
    }

    fun isReceiverEnabled(): Boolean = synchronized(lock) { state.receiverEnabled }

    fun setReceiverEnabled(enabled: Boolean) {
        synchronized(lock) {
            state.receiverEnabled = enabled
            store.save(state)
            syncListenerLocked()
        }
        onStateChanged?.invoke()
    }

    fun listeningPort(): Int = actualPort

    fun updateDiscoveredDevices(list: List<DiscoveredDevice>) {
        synchronized(lock) {
            discoveredMap.clear()
            for (d in list) {
                if (d.deviceID != state.identity.deviceID) {
                    discoveredMap[d.deviceID] = d
                }
            }
        }
    }

    fun start() {
        synchronized(lock) { syncListenerLocked() }
    }

    fun shutdown() {
        synchronized(lock) {
            closed = true
            activePairing?.expireFuture?.cancel(false)
            activePairing = null
            try { serverSocket?.close() } catch (_: Exception) {}
            serverSocket = null
            actualPort = 0
            advertiseHook?.invoke(false, 0, false, state.identity.deviceID, state.identity.displayName)
        }
        ioPool.shutdownNow()
        scheduler.shutdownNow()
    }

    fun startPairingCodeSession(): Pair<String, Long> {
        val code = LanClipCrypto.randomSixDigitCode()
        val expiresAt = System.currentTimeMillis() + 180_000L
        synchronized(lock) {
            activePairing?.expireFuture?.cancel(false)
            val sess = PairingSession(code, expiresAt)
            sess.expireFuture = scheduler.schedule({
                var expired = false
                synchronized(lock) {
                    if (activePairing === sess) {
                        activePairing = null
                        syncListenerLocked()
                        expired = true
                    }
                }
                if (expired) {
                    onStateChanged?.invoke()
                    onPairingExpired?.invoke()
                }
            }, 180, TimeUnit.SECONDS)
            activePairing = sess
            syncListenerLocked()
        }
        onStateChanged?.invoke()
        return code to expiresAt
    }

    fun cancelPairingCodeSession() {
        synchronized(lock) {
            activePairing?.expireFuture?.cancel(false)
            activePairing = null
            syncListenerLocked()
        }
        onStateChanged?.invoke()
    }

    private fun shouldListenLocked(): Boolean {
        if (closed) return false
        if (activePairing != null) return true
        return state.peers.isNotEmpty() && state.receiverEnabled
    }

    private fun syncListenerLocked() {
        val needed = shouldListenLocked()
        if (!needed) {
            try { serverSocket?.close() } catch (_: Exception) {}
            serverSocket = null
            actualPort = 0
            advertiseHook?.invoke(false, 0, false, state.identity.deviceID, state.identity.displayName)
            return
        }

        if (serverSocket == null) {
            val srv = try {
                ServerSocket().apply {
                    reuseAddress = true
                    bind(InetSocketAddress(preferredPort))
                }
            } catch (_: Exception) {
                if (preferredPort != 0) ServerSocket(0) else throw IllegalStateException("无法绑定监听端口")
            }
            serverSocket = srv
            actualPort = srv.localPort
            ioPool.submit { acceptLoop(srv) }
        }
        advertiseHook?.invoke(true, actualPort, activePairing != null, state.identity.deviceID, state.identity.displayName)
    }

    private fun acceptLoop(srv: ServerSocket) {
        while (!srv.isClosed) {
            val sock = try {
                srv.accept()
            } catch (_: Exception) {
                break
            }
            if (!LanClipCrypto.isAllowedAddress(sock.inetAddress)) {
                try { sock.close() } catch (_: Exception) {}
                continue
            }
            if (!sem.tryAcquire()) {
                try { sock.close() } catch (_: Exception) {}
                continue
            }
            ioPool.submit {
                try {
                    handleConnection(sock)
                } finally {
                    try { sock.close() } catch (_: Exception) {}
                    sem.release()
                }
            }
        }
    }

    private fun handleConnection(sock: Socket) {
        sock.soTimeout = 8_000
        val (mType, body) = try {
            LanClipCrypto.readFrame(sock.getInputStream())
        } catch (_: Exception) {
            return
        }
        val remoteIP = sock.inetAddress?.hostAddress ?: ""
        when (mType) {
            LanClipCrypto.MSG_PAIR_INIT -> handleIncomingPair(sock, body, remoteIP)
            LanClipCrypto.MSG_CLIP_INIT -> handleIncomingClip(sock, body, remoteIP)
            LanClipCrypto.MSG_FILE_INIT -> handleIncomingFile(sock, body, remoteIP)
        }
    }

    private fun sendError(sock: Socket, msgType: Byte, message: String) {
        try {
            val obj = JSONObject().put("message", message)
            LanClipCrypto.writeFrame(sock.getOutputStream(), msgType, obj.toString().toByteArray(Charsets.UTF_8))
        } catch (_: Exception) {}
    }

    private fun handleIncomingPair(sock: Socket, payload: ByteArray, remoteIP: String) {
        val myIdentity: DeviceIdentity
        val myPort: Int
        val valid: Boolean
        synchronized(lock) {
            myIdentity = state.identity
            myPort = if (actualPort > 0) actualPort else preferredPort
            val s = activePairing
            valid = s != null && System.currentTimeMillis() < s.expiresAtMs && s.failedAttempts < 5
        }
        if (!valid) {
            sendError(sock, LanClipCrypto.MSG_PAIR_ERROR, "对方未处于验证码配对状态，或验证码已过期。")
            return
        }

        val initJson = try { JSONObject(String(payload, Charsets.UTF_8)) } catch (_: Exception) {
            sendError(sock, LanClipCrypto.MSG_PAIR_ERROR, "配对请求格式无效。")
            return
        }
        val bDeviceID = initJson.optString("bDeviceID", "")
        val bDisplayName = initJson.optString("bDisplayName", "")
        val bSignPubB64 = initJson.optString("bSignPubB64", "")
        val bEphPubB64 = initJson.optString("bEphPubB64", "")
        val nonceBB64 = initJson.optString("nonceBB64", "")
        val bListenPort = initJson.optInt("bListenPort", LanClipCrypto.DEFAULT_PORT)

        if (bDeviceID.isEmpty() || bDeviceID == myIdentity.deviceID) {
            sendError(sock, LanClipCrypto.MSG_PAIR_ERROR, "配对请求无效。")
            return
        }
        val bSignPub = try { LanClipCrypto.b64Decode(bSignPubB64) } catch (_: Exception) { ByteArray(0) }
        val bEphPub = try { LanClipCrypto.b64Decode(bEphPubB64) } catch (_: Exception) { ByteArray(0) }
        val nonceB = try { LanClipCrypto.b64Decode(nonceBB64) } catch (_: Exception) { ByteArray(0) }
        if (bSignPub.size != 32 || bEphPub.size != 32) {
            sendError(sock, LanClipCrypto.MSG_PAIR_ERROR, "配对请求公钥无效。")
            return
        }

        val aSignPub = LanClipCrypto.ed25519PubFromSeed(myIdentity.seedBytes())
        val (aEphPriv, aEphPub) = LanClipCrypto.generateX25519Keypair()
        val nonceA = LanClipCrypto.randomBytes(16)
        val salt = LanClipCrypto.randomBytes(16)

        val chal = JSONObject()
            .put("aDeviceID", myIdentity.deviceID)
            .put("aDisplayName", myIdentity.displayName)
            .put("aSignPubB64", LanClipCrypto.b64Encode(aSignPub))
            .put("aEphPubB64", LanClipCrypto.b64Encode(aEphPub))
            .put("nonceAB64", LanClipCrypto.b64Encode(nonceA))
            .put("saltB64", LanClipCrypto.b64Encode(salt))
            .put("aListenPort", myPort)

        try {
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_PAIR_CHALLENGE, chal.toString().toByteArray(Charsets.UTF_8))
        } catch (_: Exception) { return }

        val (pType, pBody) = try { LanClipCrypto.readFrame(sock.getInputStream()) } catch (_: Exception) { return }
        if (pType != LanClipCrypto.MSG_PAIR_PROOF_B) return
        val proofB = try {
            LanClipCrypto.b64Decode(JSONObject(String(pBody, Charsets.UTF_8)).getString("proofB64"))
        } catch (_: Exception) { return }

        val shared = LanClipCrypto.x25519Shared(aEphPriv, bEphPub)
        val tx = LanClipCrypto.computePairTranscript(myIdentity.deviceID, bDeviceID, aSignPub, bSignPub, aEphPub, bEphPub, nonceA, nonceB, salt)

        val macKey: ByteArray
        val newPeer: PairedPeer
        synchronized(lock) {
            val sess = activePairing
            if (sess == null || System.currentTimeMillis() >= sess.expiresAtMs || sess.failedAttempts >= 5) {
                sendError(sock, LanClipCrypto.MSG_PAIR_ERROR, "验证码已失效，请重新生成。")
                return
            }
            val pwKey = LanClipCrypto.pbkdf2Sha256(sess.code, salt)
            macKey = LanClipCrypto.derivePairMacKey(shared, pwKey, salt)
            if (!LanClipCrypto.verifyPairProof(proofB, "PROOF-B", tx, macKey)) {
                sess.failedAttempts += 1
                if (sess.failedAttempts >= 5) {
                    sess.expireFuture?.cancel(false)
                    activePairing = null
                    syncListenerLocked()
                    onStateChanged?.invoke()
                    sendError(sock, LanClipCrypto.MSG_PAIR_ERROR, "验证码连续输错 5 次，已锁定失效，请在对方设备重新生成。")
                } else {
                    val left = 5 - sess.failedAttempts
                    sendError(sock, LanClipCrypto.MSG_PAIR_ERROR, "验证码不正确，还可再试 $left 次。")
                }
                return
            }
            sess.expireFuture?.cancel(false)
            activePairing = null
            newPeer = PairedPeer(
                deviceID = bDeviceID,
                displayName = bDisplayName,
                ed25519PublicKeyB64 = bSignPubB64,
                lastHost = remoteIP,
                lastPort = if (bListenPort > 0) bListenPort else LanClipCrypto.DEFAULT_PORT,
                pairedAtMs = System.currentTimeMillis()
            )
            upsertPeerLocked(newPeer)
            state.receiverEnabled = true
            store.save(state)
            syncListenerLocked()
        }

        val proofA = LanClipCrypto.computePairProof("PROOF-A", tx, macKey)
        val proofAMsg = JSONObject().put("proofB64", LanClipCrypto.b64Encode(proofA))
        try {
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_PAIR_PROOF_A, proofAMsg.toString().toByteArray(Charsets.UTF_8))
        } catch (_: Exception) {}

        onStateChanged?.invoke()
        onPairingCompleted?.invoke(newPeer)
    }

    private fun handleIncomingClip(sock: Socket, payload: ByteArray, remoteIP: String) {
        val initJson = try { JSONObject(String(payload, Charsets.UTF_8)) } catch (_: Exception) {
            sendError(sock, LanClipCrypto.MSG_CLIP_ERROR, "请求格式无效。")
            return
        }
        val senderID = initJson.optString("senderDeviceID", "")
        val peer: PairedPeer?
        val enabled: Boolean
        val myID: DeviceIdentity
        synchronized(lock) {
            enabled = state.receiverEnabled
            peer = findPeerLocked(senderID)
            myID = state.identity
        }
        if (!enabled || peer == null) {
            sendError(sock, LanClipCrypto.MSG_CLIP_ERROR, "接收方未开启接收或发送方未在信任列表。")
            return
        }

        val ephPubA = try { LanClipCrypto.b64Decode(initJson.getString("ephPubAB64")) } catch (_: Exception) { ByteArray(0) }
        val nonceA = try { LanClipCrypto.b64Decode(initJson.getString("nonceAB64")) } catch (_: Exception) { ByteArray(0) }
        val sigA = try { LanClipCrypto.b64Decode(initJson.getString("sigAB64")) } catch (_: Exception) { ByteArray(0) }
        if (ephPubA.size != 32 || !LanClipCrypto.ed25519Verify(peer.publicKeyBytes(), LanClipCrypto.clipInitSignData(peer.deviceID, myID.deviceID, ephPubA, nonceA), sigA)) {
            sendError(sock, LanClipCrypto.MSG_CLIP_ERROR, "对方签名验证未通过，已拒绝连接。")
            return
        }

        val (ephPrivB, ephPubB) = LanClipCrypto.generateX25519Keypair()
        val nonceB = LanClipCrypto.randomBytes(16)
        val sigB = LanClipCrypto.ed25519Sign(myID.seedBytes(), LanClipCrypto.clipChallengeSignData(myID.deviceID, peer.deviceID, ephPubA, nonceA, ephPubB, nonceB))
        val chal = JSONObject()
            .put("ephPubBB64", LanClipCrypto.b64Encode(ephPubB))
            .put("nonceBB64", LanClipCrypto.b64Encode(nonceB))
            .put("sigBB64", LanClipCrypto.b64Encode(sigB))
        try {
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_CLIP_CHALLENGE, chal.toString().toByteArray(Charsets.UTF_8))
        } catch (_: Exception) { return }

        val (pType, pBody) = try { LanClipCrypto.readFrame(sock.getInputStream()) } catch (_: Exception) { return }
        if (pType != LanClipCrypto.MSG_CLIP_PAYLOAD) return
        val combined = try {
            LanClipCrypto.b64Decode(JSONObject(String(pBody, Charsets.UTF_8)).getString("combinedB64"))
        } catch (_: Exception) { return }

        val shared = LanClipCrypto.x25519Shared(ephPrivB, ephPubA)
        val tx = LanClipCrypto.clipTranscriptHash(peer.deviceID, myID.deviceID, ephPubA, nonceA, ephPubB, nonceB)
        val sessKey = LanClipCrypto.deriveClipSessionKey(shared, tx)
        val plain = try {
            LanClipCrypto.openClipData(combined, "PAYLOAD", tx, sessKey)
        } catch (_: Exception) { return }
        if (plain.isEmpty() || plain.size > LanClipCrypto.MAX_CLIP_BYTES) return

        synchronized(lock) {
            val p = findPeerLocked(peer.deviceID)
            if (p != null && remoteIP.isNotEmpty() && p.lastHost != remoteIP) {
                p.lastHost = remoteIP
                store.save(state)
            }
        }
        val text = String(plain, Charsets.UTF_8)
        onTextReceived?.invoke(text, peer.displayName)

        val ackBytes = LanClipCrypto.sealClipData("OK".toByteArray(Charsets.UTF_8), "ACK", tx, sessKey)
        val ackObj = JSONObject().put("combinedB64", LanClipCrypto.b64Encode(ackBytes))
        try {
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_CLIP_ACK, ackObj.toString().toByteArray(Charsets.UTF_8))
        } catch (_: Exception) {}
    }

    private fun handleIncomingFile(sock: Socket, payload: ByteArray, remoteIP: String) {
        sock.soTimeout = 30_000
        val initJson = try { JSONObject(String(payload, Charsets.UTF_8)) } catch (_: Exception) {
            sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "文件请求格式无效。")
            return
        }
        val senderID = initJson.optString("senderDeviceID", "")
        val peer: PairedPeer?
        val enabled: Boolean
        val myID: DeviceIdentity
        synchronized(lock) {
            enabled = state.receiverEnabled
            peer = findPeerLocked(senderID)
            myID = state.identity
        }
        if (!enabled || peer == null) {
            sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "接收方未开启接收或发送方未在信任列表。")
            return
        }

        val ephPubA = try { LanClipCrypto.b64Decode(initJson.getString("ephPubAB64")) } catch (_: Exception) { ByteArray(0) }
        val nonceA = try { LanClipCrypto.b64Decode(initJson.getString("nonceAB64")) } catch (_: Exception) { ByteArray(0) }
        val sigA = try { LanClipCrypto.b64Decode(initJson.getString("sigAB64")) } catch (_: Exception) { ByteArray(0) }
        if (ephPubA.size != 32 || !LanClipCrypto.ed25519Verify(peer.publicKeyBytes(), LanClipCrypto.fileInitSignData(peer.deviceID, myID.deviceID, ephPubA, nonceA), sigA)) {
            sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "对方签名验证未通过，已拒绝文件传输。")
            return
        }

        val (ephPrivB, ephPubB) = LanClipCrypto.generateX25519Keypair()
        val nonceB = LanClipCrypto.randomBytes(16)
        val sigB = LanClipCrypto.ed25519Sign(myID.seedBytes(), LanClipCrypto.fileChallengeSignData(myID.deviceID, peer.deviceID, ephPubA, nonceA, ephPubB, nonceB))
        val shared = LanClipCrypto.x25519Shared(ephPrivB, ephPubA)
        val tx = LanClipCrypto.fileTranscriptHash(peer.deviceID, myID.deviceID, ephPubA, nonceA, ephPubB, nonceB)
        val (sessKey, nonceBase) = LanClipCrypto.deriveFileSessionKeys(shared, tx)

        val chal = JSONObject()
            .put("ephPubBB64", LanClipCrypto.b64Encode(ephPubB))
            .put("nonceBB64", LanClipCrypto.b64Encode(nonceB))
            .put("sigBB64", LanClipCrypto.b64Encode(sigB))
        try {
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_FILE_CHALLENGE, chal.toString().toByteArray(Charsets.UTF_8))
        } catch (_: Exception) { return }

        val (mType, metaBody) = try { LanClipCrypto.readFrame(sock.getInputStream()) } catch (_: Exception) { return }
        if (mType != LanClipCrypto.MSG_FILE_META) return
        val metaObj = try {
            val plainMeta = LanClipCrypto.openFileRaw(metaBody, sessKey, nonceBase, LanClipCrypto.FILE_SEQ_META, LanClipCrypto.fileAAD("FILE-META", null, tx))
            JSONObject(String(plainMeta, Charsets.UTF_8))
        } catch (_: Exception) {
            sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "文件元信息解密失败。")
            return
        }

        val rawName = metaObj.optString("fileName", "")
        val fileSize = metaObj.optLong("fileSize", -1L)
        val chunkSize = metaObj.optInt("chunkSize", 0)
        if (fileSize < 0L || fileSize > LanClipCrypto.MAX_FILE_BYTES || chunkSize <= 0 || chunkSize > LanClipCrypto.FILE_CHUNK_SIZE) {
            sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "文件元信息无效或超出 4 GB 安全上限。")
            return
        }

        val sanitized = LanClipCrypto.sanitizeReceivedFileName(rawName)
        val session = try {
            fileSink.openSession(sanitized, fileSize)
        } catch (_: Exception) {
            sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "无法创建接收文件。")
            return
        }

        var committed = false
        try {
            val readyCipher = LanClipCrypto.sealFileRaw("OK".toByteArray(Charsets.UTF_8), sessKey, nonceBase, LanClipCrypto.FILE_SEQ_READY, LanClipCrypto.fileAAD("FILE-READY", null, tx))
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_FILE_READY, readyCipher)

            val md = MessageDigest.getInstance("SHA-256")
            var bytesWritten = 0L
            var expectedChunk = 1L

            while (true) {
                sock.soTimeout = 30_000
                val (ft, body) = LanClipCrypto.readFrame(sock.getInputStream())
                if (ft == LanClipCrypto.MSG_FILE_CHUNK) {
                    if (body.size < 24) {
                        sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "分片数据格式错误。")
                        return
                    }
                    val idx = ByteBuffer.wrap(body, 0, 8).order(ByteOrder.BIG_ENDIAN).long
                    if (idx != expectedChunk) {
                        sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "分片序号异常。")
                        return
                    }
                    val cipherPart = body.copyOfRange(8, body.size)
                    val chunkPlain = LanClipCrypto.openFileRaw(cipherPart, sessKey, nonceBase, idx, LanClipCrypto.fileAAD("FILE-CHUNK", idx, tx))
                    if (chunkPlain.size > chunkSize || bytesWritten + chunkPlain.size > fileSize) {
                        sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "接收大小超出声明上限。")
                        return
                    }
                    if (chunkPlain.isNotEmpty()) {
                        session.write(chunkPlain, chunkPlain.size)
                        md.update(chunkPlain)
                        bytesWritten += chunkPlain.size
                    }
                    expectedChunk++
                } else if (ft == LanClipCrypto.MSG_FILE_FINISH) {
                    val finPlain = LanClipCrypto.openFileRaw(body, sessKey, nonceBase, LanClipCrypto.FILE_SEQ_FINISH, LanClipCrypto.fileAAD("FILE-FINISH", null, tx))
                    val finObj = JSONObject(String(finPlain, Charsets.UTF_8))
                    val expectedHex = finObj.optString("sha256Hex", "")
                    val totalChunks = finObj.optLong("totalChunks", -1L)
                    val actualHex = LanClipCrypto.bytesToHex(md.digest())
                    val recvChunks = expectedChunk - 1L
                    if (bytesWritten != fileSize || recvChunks != totalChunks || !LanClipCrypto.constantTimeEqualHex(actualHex, expectedHex)) {
                        sendError(sock, LanClipCrypto.MSG_FILE_ERROR, "文件完整性校验未通过。")
                        return
                    }

                    val savedName = session.commit()
                    committed = true

                    synchronized(lock) {
                        val p = findPeerLocked(peer.deviceID)
                        if (p != null && remoteIP.isNotEmpty() && p.lastHost != remoteIP) {
                            p.lastHost = remoteIP
                            store.save(state)
                        }
                    }
                    onFileReceived?.invoke(savedName, peer.displayName)

                    val ackPlain = JSONObject().put("savedName", savedName).toString().toByteArray(Charsets.UTF_8)
                    val ackCipher = LanClipCrypto.sealFileRaw(ackPlain, sessKey, nonceBase, LanClipCrypto.FILE_SEQ_ACK, LanClipCrypto.fileAAD("FILE-ACK", null, tx))
                    LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_FILE_ACK, ackCipher)
                    return
                } else {
                    return
                }
            }
        } catch (_: Exception) {
            return
        } finally {
            if (!committed) session.abort()
        }
    }

    // Outgoing Pairing

    fun pairWithHost(host: String, port: Int, code: String): PairedPeer {
        val cleanCode = code.filter { it.isDigit() }
        require(cleanCode.length == 6) { "请输入完整的 6 位数字验证码。" }
        val trimmed = host.trim()
        require(trimmed.isNotEmpty()) { "请先选择附近的设备，或填写对方局域网 IP。" }
        val targetPort = if (port > 0) port else LanClipCrypto.DEFAULT_PORT

        val myID: DeviceIdentity
        val bPort: Int
        synchronized(lock) {
            myID = state.identity
            bPort = if (actualPort > 0) actualPort else preferredPort
        }
        val bSignPub = LanClipCrypto.ed25519PubFromSeed(myID.seedBytes())
        val (bEphPriv, bEphPub) = LanClipCrypto.generateX25519Keypair()
        val nonceB = LanClipCrypto.randomBytes(16)

        val sock = Socket()
        sock.connect(InetSocketAddress(trimmed, targetPort), 5_000)
        sock.soTimeout = 8_000
        return sock.use {
            val initObj = JSONObject()
                .put("bDeviceID", myID.deviceID)
                .put("bDisplayName", myID.displayName)
                .put("bSignPubB64", LanClipCrypto.b64Encode(bSignPub))
                .put("bEphPubB64", LanClipCrypto.b64Encode(bEphPub))
                .put("nonceBB64", LanClipCrypto.b64Encode(nonceB))
                .put("bListenPort", bPort)
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_PAIR_INIT, initObj.toString().toByteArray(Charsets.UTF_8))

            val (cType, cBody) = LanClipCrypto.readFrame(sock.getInputStream())
            if (cType == LanClipCrypto.MSG_PAIR_ERROR) {
                val msg = JSONObject(String(cBody, Charsets.UTF_8)).optString("message", "配对失败")
                throw IllegalStateException(msg)
            }
            require(cType == LanClipCrypto.MSG_PAIR_CHALLENGE) { "对方返回了无效的配对响应。" }
            val chal = JSONObject(String(cBody, Charsets.UTF_8))
            val aDeviceID = chal.getString("aDeviceID")
            val aDisplayName = chal.getString("aDisplayName")
            val aSignPubB64 = chal.getString("aSignPubB64")
            val aSignPub = LanClipCrypto.b64Decode(aSignPubB64)
            val aEphPub = LanClipCrypto.b64Decode(chal.getString("aEphPubB64"))
            val nonceA = LanClipCrypto.b64Decode(chal.getString("nonceAB64"))
            val salt = LanClipCrypto.b64Decode(chal.getString("saltB64"))
            val aListenPort = chal.optInt("aListenPort", LanClipCrypto.DEFAULT_PORT)

            val shared = LanClipCrypto.x25519Shared(bEphPriv, aEphPub)
            val pwKey = LanClipCrypto.pbkdf2Sha256(cleanCode, salt)
            val tx = LanClipCrypto.computePairTranscript(aDeviceID, myID.deviceID, aSignPub, bSignPub, aEphPub, bEphPub, nonceA, nonceB, salt)
            val macKey = LanClipCrypto.derivePairMacKey(shared, pwKey, salt)
            val proofB = LanClipCrypto.computePairProof("PROOF-B", tx, macKey)

            val pMsg = JSONObject().put("proofB64", LanClipCrypto.b64Encode(proofB))
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_PAIR_PROOF_B, pMsg.toString().toByteArray(Charsets.UTF_8))

            val (aType, aBody) = LanClipCrypto.readFrame(sock.getInputStream())
            if (aType == LanClipCrypto.MSG_PAIR_ERROR) {
                val msg = JSONObject(String(aBody, Charsets.UTF_8)).optString("message", "验证码校验失败")
                throw IllegalStateException(msg)
            }
            require(aType == LanClipCrypto.MSG_PAIR_PROOF_A) { "验证码校验未通过。" }
            val proofA = LanClipCrypto.b64Decode(JSONObject(String(aBody, Charsets.UTF_8)).getString("proofB64"))
            require(LanClipCrypto.verifyPairProof(proofA, "PROOF-A", tx, macKey)) { "验证码校验未通过，请重新确认。" }

            val resolvedIP = sock.inetAddress?.hostAddress ?: trimmed
            val peer = PairedPeer(
                deviceID = aDeviceID,
                displayName = aDisplayName,
                ed25519PublicKeyB64 = aSignPubB64,
                lastHost = resolvedIP,
                lastPort = if (aListenPort > 0) aListenPort else LanClipCrypto.DEFAULT_PORT,
                pairedAtMs = System.currentTimeMillis()
            )
            synchronized(lock) {
                upsertPeerLocked(peer)
                state.receiverEnabled = true
                store.save(state)
                syncListenerLocked()
            }
            onStateChanged?.invoke()
            peer
        }
    }

    private fun resolveTarget(peerID: String?): Triple<PairedPeer, String, Int> {
        val peer: PairedPeer
        val disc: DiscoveredDevice?
        synchronized(lock) {
            peer = (if (!peerID.isNullOrEmpty()) findPeerLocked(peerID) else activePeerLocked())
                ?: throw IllegalStateException("尚未完成设备配对，请先用 6 位验证码配对。")
            disc = discoveredMap[peer.deviceID]
        }
        if (disc != null) return Triple(peer, disc.host, disc.port)
        if (peer.lastHost.isNotEmpty()) {
            val port = if (peer.lastPort > 0) peer.lastPort else LanClipCrypto.DEFAULT_PORT
            return Triple(peer, peer.lastHost, port)
        }
        throw IllegalStateException("找不到目标设备「${peer.displayName}」的地址，请确认对方已打开软件。")
    }

    fun sendText(text: String, peerID: String? = null): Pair<Int, String> {
        val utf8 = text.toByteArray(Charsets.UTF_8)
        require(utf8.isNotEmpty()) { "当前剪贴板里没有可发送的文字。" }
        require(utf8.size <= LanClipCrypto.MAX_CLIP_BYTES) { "剪贴板文字超过 1 MB 安全上限，已取消发送。" }

        val (peer, host, port) = resolveTarget(peerID)
        val myID = currentIdentity()
        val (ephPrivA, ephPubA) = LanClipCrypto.generateX25519Keypair()
        val nonceA = LanClipCrypto.randomBytes(16)
        val sigA = LanClipCrypto.ed25519Sign(myID.seedBytes(), LanClipCrypto.clipInitSignData(myID.deviceID, peer.deviceID, ephPubA, nonceA))

        val sock = Socket()
        sock.connect(InetSocketAddress(host, port), 4_000)
        sock.soTimeout = 8_000
        return sock.use {
            val initObj = JSONObject()
                .put("senderDeviceID", myID.deviceID)
                .put("ephPubAB64", LanClipCrypto.b64Encode(ephPubA))
                .put("nonceAB64", LanClipCrypto.b64Encode(nonceA))
                .put("sigAB64", LanClipCrypto.b64Encode(sigA))
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_CLIP_INIT, initObj.toString().toByteArray(Charsets.UTF_8))

            val (cType, cBody) = LanClipCrypto.readFrame(sock.getInputStream())
            if (cType == LanClipCrypto.MSG_CLIP_ERROR) {
                throw IllegalStateException(JSONObject(String(cBody, Charsets.UTF_8)).optString("message", "对方拒绝接收。"))
            }
            require(cType == LanClipCrypto.MSG_CLIP_CHALLENGE) { "安全拦截：对方设备响应格式异常。" }
            val chal = JSONObject(String(cBody, Charsets.UTF_8))
            val ephPubB = LanClipCrypto.b64Decode(chal.getString("ephPubBB64"))
            val nonceB = LanClipCrypto.b64Decode(chal.getString("nonceBB64"))
            val sigB = LanClipCrypto.b64Decode(chal.getString("sigBB64"))
            require(ephPubB.size == 32 && LanClipCrypto.ed25519Verify(peer.publicKeyBytes(), LanClipCrypto.clipChallengeSignData(peer.deviceID, myID.deviceID, ephPubA, nonceA, ephPubB, nonceB), sigB)) {
                "安全拦截：对方身份签名校验未通过，已中止发送。"
            }

            val shared = LanClipCrypto.x25519Shared(ephPrivA, ephPubB)
            val tx = LanClipCrypto.clipTranscriptHash(myID.deviceID, peer.deviceID, ephPubA, nonceA, ephPubB, nonceB)
            val sessKey = LanClipCrypto.deriveClipSessionKey(shared, tx)
            val sealed = LanClipCrypto.sealClipData(utf8, "PAYLOAD", tx, sessKey)
            val payObj = JSONObject().put("combinedB64", LanClipCrypto.b64Encode(sealed))
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_CLIP_PAYLOAD, payObj.toString().toByteArray(Charsets.UTF_8))

            val (aType, aBody) = LanClipCrypto.readFrame(sock.getInputStream())
            require(aType == LanClipCrypto.MSG_CLIP_ACK) { "未能确认对方已接收文字。" }
            val ackBytes = LanClipCrypto.b64Decode(JSONObject(String(aBody, Charsets.UTF_8)).getString("combinedB64"))
            val ackPlain = LanClipCrypto.openClipData(ackBytes, "ACK", tx, sessKey)
            require(String(ackPlain, Charsets.UTF_8) == "OK") { "未能确认对方已接收文字。" }

            text.length to peer.displayName
        }
    }

    fun sendFile(file: File, peerID: String? = null): Pair<String, String> {
        require(file.exists() && file.isFile) { "无法读取选中的文件。" }
        return FileInputStream(file).use { fis ->
            sendFileStream(file.name, file.length(), fis, peerID)
        }
    }

    fun sendFileStream(fileName: String, fileSize: Long, input: InputStream, peerID: String? = null): Pair<String, String> {
        require(fileSize in 0..LanClipCrypto.MAX_FILE_BYTES) { "文件超过 4 GB 单文件上限，已取消发送。" }

        val (peer, host, port) = resolveTarget(peerID)
        val myID = currentIdentity()
        val (ephPrivA, ephPubA) = LanClipCrypto.generateX25519Keypair()
        val nonceA = LanClipCrypto.randomBytes(16)
        val sigA = LanClipCrypto.ed25519Sign(myID.seedBytes(), LanClipCrypto.fileInitSignData(myID.deviceID, peer.deviceID, ephPubA, nonceA))

        val sock = Socket()
        sock.connect(InetSocketAddress(host, port), 5_000)
        sock.soTimeout = 30_000
        return sock.use {
            val initObj = JSONObject()
                .put("senderDeviceID", myID.deviceID)
                .put("ephPubAB64", LanClipCrypto.b64Encode(ephPubA))
                .put("nonceAB64", LanClipCrypto.b64Encode(nonceA))
                .put("sigAB64", LanClipCrypto.b64Encode(sigA))
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_FILE_INIT, initObj.toString().toByteArray(Charsets.UTF_8))

            val (cType, cBody) = LanClipCrypto.readFrame(sock.getInputStream())
            if (cType == LanClipCrypto.MSG_FILE_ERROR) {
                throw IllegalStateException(JSONObject(String(cBody, Charsets.UTF_8)).optString("message", "对方拒绝接收文件。"))
            }
            require(cType == LanClipCrypto.MSG_FILE_CHALLENGE) { "安全拦截：对方设备文件握手响应异常。" }
            val chal = JSONObject(String(cBody, Charsets.UTF_8))
            val ephPubB = LanClipCrypto.b64Decode(chal.getString("ephPubBB64"))
            val nonceB = LanClipCrypto.b64Decode(chal.getString("nonceBB64"))
            val sigB = LanClipCrypto.b64Decode(chal.getString("sigBB64"))
            require(ephPubB.size == 32 && LanClipCrypto.ed25519Verify(peer.publicKeyBytes(), LanClipCrypto.fileChallengeSignData(peer.deviceID, myID.deviceID, ephPubA, nonceA, ephPubB, nonceB), sigB)) {
                "安全拦截：对方身份签名校验未通过，已中止发送文件。"
            }

            val shared = LanClipCrypto.x25519Shared(ephPrivA, ephPubB)
            val tx = LanClipCrypto.fileTranscriptHash(myID.deviceID, peer.deviceID, ephPubA, nonceA, ephPubB, nonceB)
            val (sessKey, nonceBase) = LanClipCrypto.deriveFileSessionKeys(shared, tx)

            val metaPlain = JSONObject()
                .put("fileName", fileName)
                .put("fileSize", fileSize)
                .put("chunkSize", LanClipCrypto.FILE_CHUNK_SIZE)
                .toString()
                .toByteArray(Charsets.UTF_8)
            val metaCipher = LanClipCrypto.sealFileRaw(metaPlain, sessKey, nonceBase, LanClipCrypto.FILE_SEQ_META, LanClipCrypto.fileAAD("FILE-META", null, tx))
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_FILE_META, metaCipher)

            val (rType, rBody) = LanClipCrypto.readFrame(sock.getInputStream())
            if (rType == LanClipCrypto.MSG_FILE_ERROR) {
                throw IllegalStateException(JSONObject(String(rBody, Charsets.UTF_8)).optString("message", "对方未准备好接收文件。"))
            }
            require(rType == LanClipCrypto.MSG_FILE_READY) { "对方未准备好接收文件。" }
            val readyPlain = LanClipCrypto.openFileRaw(rBody, sessKey, nonceBase, LanClipCrypto.FILE_SEQ_READY, LanClipCrypto.fileAAD("FILE-READY", null, tx))
            require(String(readyPlain, Charsets.UTF_8) == "OK") { "对方未准备好接收文件。" }

            val buf = ByteArray(LanClipCrypto.FILE_CHUNK_SIZE)
            val md = MessageDigest.getInstance("SHA-256")
            var chunkIndex = 1L

            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                val slice = if (n == buf.size) buf else buf.copyOfRange(0, n)
                md.update(slice)
                val cipher = LanClipCrypto.sealFileRaw(slice, sessKey, nonceBase, chunkIndex, LanClipCrypto.fileAAD("FILE-CHUNK", chunkIndex, tx))
                val frameBody = LanClipCrypto.uint64BE(chunkIndex) + cipher
                LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_FILE_CHUNK, frameBody)
                chunkIndex++
            }

            val totalChunks = chunkIndex - 1L
            val shaHex = LanClipCrypto.bytesToHex(md.digest())
            val finPlain = JSONObject()
                .put("sha256Hex", shaHex)
                .put("totalChunks", totalChunks)
                .toString()
                .toByteArray(Charsets.UTF_8)
            val finCipher = LanClipCrypto.sealFileRaw(finPlain, sessKey, nonceBase, LanClipCrypto.FILE_SEQ_FINISH, LanClipCrypto.fileAAD("FILE-FINISH", null, tx))
            LanClipCrypto.writeFrame(sock.getOutputStream(), LanClipCrypto.MSG_FILE_FINISH, finCipher)

            val (aType, aBody) = LanClipCrypto.readFrame(sock.getInputStream())
            if (aType == LanClipCrypto.MSG_FILE_ERROR) {
                throw IllegalStateException(JSONObject(String(aBody, Charsets.UTF_8)).optString("message", "文件校验未通过。"))
            }
            require(aType == LanClipCrypto.MSG_FILE_ACK) { "未能确认对方已完成文件校验保存。" }
            val ackPlain = LanClipCrypto.openFileRaw(aBody, sessKey, nonceBase, LanClipCrypto.FILE_SEQ_ACK, LanClipCrypto.fileAAD("FILE-ACK", null, tx))
            val savedName = JSONObject(String(ackPlain, Charsets.UTF_8)).getString("savedName")
            savedName to peer.displayName
        }
    }
}
