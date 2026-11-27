package com.local.lanclip.core

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.nio.file.Files
import java.nio.file.StandardCopyOption

data class DeviceIdentity(
    val deviceID: String,
    val displayName: String,
    val ed25519PrivateKeyB64: String
) {
    fun seedBytes(): ByteArray = LanClipCrypto.b64Decode(ed25519PrivateKeyB64)
}

data class PairedPeer(
    val deviceID: String,
    val displayName: String,
    val ed25519PublicKeyB64: String,
    var lastHost: String,
    var lastPort: Int,
    val pairedAtMs: Long
) {
    fun publicKeyBytes(): ByteArray = LanClipCrypto.b64Decode(ed25519PublicKeyB64)
}

data class PersistedState(
    val identity: DeviceIdentity,
    val peers: MutableList<PairedPeer>,
    var activePeerID: String?,
    var receiverEnabled: Boolean
)

class StateStore(private val stateFile: File, defaultDisplayName: String) {
    private val defaultName = defaultDisplayName.ifBlank { "Android-Device" }

    @Synchronized
    fun loadOrCreate(): PersistedState {
        val dir = stateFile.parentFile
        if (dir != null && !dir.exists()) dir.mkdirs()

        if (stateFile.exists()) {
            val text = stateFile.readText(Charsets.UTF_8)
            val root = JSONObject(text)
            val idObj = root.getJSONObject("identity")
            val identity = DeviceIdentity(
                deviceID = idObj.getString("deviceID"),
                displayName = idObj.getString("displayName"),
                ed25519PrivateKeyB64 = idObj.getString("ed25519PrivateKeyB64")
            )
            require(identity.seedBytes().size == 32) { "Invalid identity key" }

            val peersList = mutableListOf<PairedPeer>()
            val peersArr = root.optJSONArray("peers")
            if (peersArr != null) {
                for (i in 0 until peersArr.length()) {
                    val po = peersArr.getJSONObject(i)
                    peersList.add(
                        PairedPeer(
                            deviceID = po.getString("deviceID"),
                            displayName = po.getString("displayName"),
                            ed25519PublicKeyB64 = po.getString("ed25519PublicKeyB64"),
                            lastHost = po.optString("lastHost", ""),
                            lastPort = po.optInt("lastPort", LanClipCrypto.DEFAULT_PORT),
                            pairedAtMs = po.optLong("pairedAtMs", 0L)
                        )
                    )
                }
            }
            val activeID = if (root.has("activePeerID") && !root.isNull("activePeerID")) {
                root.getString("activePeerID")
            } else {
                peersList.firstOrNull()?.deviceID
            }
            val recvOn = root.optBoolean("receiverEnabled", true)
            return PersistedState(identity, peersList, activeID, recvOn)
        }

        val (seed, _) = LanClipCrypto.generateEd25519Keypair()
        val idHex = LanClipCrypto.bytesToHex(LanClipCrypto.randomBytes(8))
        val identity = DeviceIdentity(
            deviceID = idHex,
            displayName = defaultName,
            ed25519PrivateKeyB64 = LanClipCrypto.b64Encode(seed)
        )
        val fresh = PersistedState(identity, mutableListOf(), null, true)
        save(fresh)
        return fresh
    }

    @Synchronized
    fun save(state: PersistedState) {
        val dir = stateFile.parentFile ?: File(".")
        if (!dir.exists()) dir.mkdirs()

        val root = JSONObject()
        val idObj = JSONObject()
        idObj.put("deviceID", state.identity.deviceID)
        idObj.put("displayName", state.identity.displayName)
        idObj.put("ed25519PrivateKeyB64", state.identity.ed25519PrivateKeyB64)
        root.put("identity", idObj)

        val arr = JSONArray()
        for (p in state.peers) {
            val po = JSONObject()
            po.put("deviceID", p.deviceID)
            po.put("displayName", p.displayName)
            po.put("ed25519PublicKeyB64", p.ed25519PublicKeyB64)
            po.put("lastHost", p.lastHost)
            po.put("lastPort", p.lastPort)
            po.put("pairedAtMs", p.pairedAtMs)
            arr.put(po)
        }
        root.put("peers", arr)
        root.put("activePeerID", state.activePeerID)
        root.put("receiverEnabled", state.receiverEnabled)

        val tmp = File(dir, ".state.tmp.${System.nanoTime()}")
        tmp.writeText(root.toString(2), Charsets.UTF_8)
        tmp.setReadable(false, false)
        tmp.setReadable(true, true)
        tmp.setWritable(false, false)
        tmp.setWritable(true, true)
        try {
            Files.move(tmp.toPath(), stateFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE)
        } catch (_: Exception) {
            if (!tmp.renameTo(stateFile)) {
                stateFile.writeText(root.toString(2), Charsets.UTF_8)
                tmp.delete()
            }
        }
    }
}
