package com.local.lanclip

import com.local.lanclip.core.DirectoryFileReceiveSink
import com.local.lanclip.core.LanClipCrypto
import com.local.lanclip.core.LanClipEngine
import com.local.lanclip.core.StateStore
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.net.InetAddress
import java.net.ServerSocket
import java.nio.file.Files
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class ProtocolVectorTest {
    private fun findVectorsFile(): File {
        val candidates = listOf(
            File("../../protocol/test_vectors.json"),
            File("../protocol/test_vectors.json"),
            File("protocol/test_vectors.json")
        )
        return candidates.firstOrNull { it.exists() }
            ?: error("Cannot locate protocol/test_vectors.json from ${File(".").absolutePath}")
    }

    private fun pickFreePort(): Int = ServerSocket(0).use { it.localPort }

    @Test
    fun verifySharedTestVectors() {
        val root = JSONObject(findVectorsFile().readText(Charsets.UTF_8))

        val ed = root.getJSONObject("ed25519")
        val privSeed = LanClipCrypto.hexToBytes(ed.getString("privHex"))
        val pubExpected = LanClipCrypto.hexToBytes(ed.getString("pubHex"))
        val msg = LanClipCrypto.hexToBytes(ed.getString("msgHex"))
        val swiftSig = LanClipCrypto.hexToBytes(ed.getString("sigHex"))
        assertArrayEquals(pubExpected, LanClipCrypto.ed25519PubFromSeed(privSeed))
        assertTrue(LanClipCrypto.ed25519Verify(pubExpected, msg, swiftSig))
        val kotlinSig = LanClipCrypto.ed25519Sign(privSeed, msg)
        assertTrue(LanClipCrypto.ed25519Verify(pubExpected, msg, kotlinSig))

        val pv = root.getJSONObject("pairing")
        val shared = LanClipCrypto.x25519Shared(
            LanClipCrypto.hexToBytes(pv.getString("aEphPrivHex")),
            LanClipCrypto.hexToBytes(pv.getString("bEphPubHex"))
        )
        assertEquals(pv.getString("sharedSecretHex"), LanClipCrypto.bytesToHex(shared))
        val pwKey = LanClipCrypto.pbkdf2Sha256(pv.getString("code"), LanClipCrypto.hexToBytes(pv.getString("saltHex")))
        assertEquals(pv.getString("pwKeyHex"), LanClipCrypto.bytesToHex(pwKey))
        val pairTx = LanClipCrypto.computePairTranscript(
            pv.getString("aDeviceID"), pv.getString("bDeviceID"),
            LanClipCrypto.hexToBytes(pv.getString("aSignPubHex")),
            LanClipCrypto.hexToBytes(pv.getString("bSignPubHex")),
            LanClipCrypto.hexToBytes(pv.getString("aEphPubHex")),
            LanClipCrypto.hexToBytes(pv.getString("bEphPubHex")),
            LanClipCrypto.hexToBytes(pv.getString("nonceAHex")),
            LanClipCrypto.hexToBytes(pv.getString("nonceBHex")),
            LanClipCrypto.hexToBytes(pv.getString("saltHex"))
        )
        assertEquals(pv.getString("transcriptHex"), LanClipCrypto.bytesToHex(pairTx))
        val macKey = LanClipCrypto.derivePairMacKey(shared, pwKey, LanClipCrypto.hexToBytes(pv.getString("saltHex")))
        assertEquals(pv.getString("macKeyHex"), LanClipCrypto.bytesToHex(macKey))
        assertTrue(LanClipCrypto.verifyPairProof(LanClipCrypto.hexToBytes(pv.getString("proofBHex")), "PROOF-B", pairTx, macKey))
        assertTrue(LanClipCrypto.verifyPairProof(LanClipCrypto.hexToBytes(pv.getString("proofAHex")), "PROOF-A", pairTx, macKey))

        val cv = root.getJSONObject("clipboard")
        val clipTx = LanClipCrypto.clipTranscriptHash(
            cv.getString("senderID"), cv.getString("receiverID"),
            LanClipCrypto.hexToBytes(cv.getString("ephPubAHex")),
            LanClipCrypto.hexToBytes(cv.getString("nonceAHex")),
            LanClipCrypto.hexToBytes(cv.getString("ephPubBHex")),
            LanClipCrypto.hexToBytes(cv.getString("nonceBHex"))
        )
        assertEquals(cv.getString("txHashHex"), LanClipCrypto.bytesToHex(clipTx))
        val clipKey = LanClipCrypto.deriveClipSessionKey(shared, clipTx)
        assertEquals(cv.getString("sessionKeyHex"), LanClipCrypto.bytesToHex(clipKey))
        val clipPlain = LanClipCrypto.openClipData(LanClipCrypto.b64Decode(cv.getString("combinedB64")), "PAYLOAD", clipTx, clipKey)
        assertEquals(cv.getString("plainHex"), LanClipCrypto.bytesToHex(clipPlain))

        val fv = root.getJSONObject("file")
        val fileTx = LanClipCrypto.fileTranscriptHash(
            fv.getString("senderID"), fv.getString("receiverID"),
            LanClipCrypto.hexToBytes(fv.getString("ephPubAHex")),
            LanClipCrypto.hexToBytes(fv.getString("nonceAHex")),
            LanClipCrypto.hexToBytes(fv.getString("ephPubBHex")),
            LanClipCrypto.hexToBytes(fv.getString("nonceBHex"))
        )
        assertEquals(fv.getString("txHashHex"), LanClipCrypto.bytesToHex(fileTx))
        val (fileKey, nonceBase) = LanClipCrypto.deriveFileSessionKeys(shared, fileTx)
        assertEquals(fv.getString("sessionKeyHex"), LanClipCrypto.bytesToHex(fileKey))
        assertEquals(fv.getString("nonceBaseHex"), LanClipCrypto.bytesToHex(nonceBase))

        fun checkFile(seqStr: String, label: String, seqPrefix: Long?, plainKey: String, cipherKey: String) {
            val seq = java.lang.Long.parseUnsignedLong(seqStr)
            val aad = LanClipCrypto.fileAAD(label, seqPrefix, fileTx)
            val plain = LanClipCrypto.hexToBytes(fv.getString(plainKey))
            val sealed = LanClipCrypto.sealFileRaw(plain, fileKey, nonceBase, seq, aad)
            assertEquals(fv.getString(cipherKey), LanClipCrypto.bytesToHex(sealed))
            val opened = LanClipCrypto.openFileRaw(sealed, fileKey, nonceBase, seq, aad)
            assertArrayEquals(plain, opened)
        }

        checkFile(fv.getString("metaSeq"), "FILE-META", null, "metaPlainHex", "metaCipherHex")
        checkFile(fv.getString("readySeq"), "FILE-READY", null, "readyPlainHex", "readyCipherHex")
        checkFile(fv.getString("chunk1Seq"), "FILE-CHUNK", 1L, "chunk1PlainHex", "chunk1CipherHex")
        checkFile(fv.getString("chunk2Seq"), "FILE-CHUNK", 2L, "chunk2PlainHex", "chunk2CipherHex")
        checkFile(fv.getString("finishSeq"), "FILE-FINISH", null, "finishPlainHex", "finishCipherHex")
        checkFile(fv.getString("ackSeq"), "FILE-ACK", null, "ackPlainHex", "ackCipherHex")
    }

    @Test
    fun verifyAllowlistAndSanitizer() {
        assertTrue(LanClipCrypto.isAllowedAddress(InetAddress.getByName("192.168.1.10")))
        assertTrue(LanClipCrypto.isAllowedAddress(InetAddress.getByName("10.0.0.1")))
        assertTrue(LanClipCrypto.isAllowedAddress(InetAddress.getByName("172.16.0.1")))
        assertTrue(LanClipCrypto.isAllowedAddress(InetAddress.getByName("127.0.0.1")))
        assertFalse(LanClipCrypto.isAllowedAddress(InetAddress.getByName("198.18.0.1")))
        assertFalse(LanClipCrypto.isAllowedAddress(InetAddress.getByName("8.8.8.8")))

        assertEquals("passwd", LanClipCrypto.sanitizeReceivedFileName("../../etc/passwd"))
        assertEquals("evil.exe", LanClipCrypto.sanitizeReceivedFileName("..\\..\\Windows\\System32\\evil.exe"))
        assertEquals("received_file", LanClipCrypto.sanitizeReceivedFileName("CON.txt"))
        assertEquals("received_file", LanClipCrypto.sanitizeReceivedFileName("nul"))
    }

    @Test
    fun endToEndKotlinEngine() {
        val tmp = Files.createTempDirectory("lanclip_android_test").toFile()
        try {
            val portA = pickFreePort()
            val portB = pickFreePort()
            val dlB = File(tmp, "b/dl")
            val engA = LanClipEngine(StateStore(File(tmp, "a/state.json"), "Android-A"), DirectoryFileReceiveSink(File(tmp, "a/dl")), portA)
            val engB = LanClipEngine(StateStore(File(tmp, "b/state.json"), "Mac-B"), DirectoryFileReceiveSink(dlB), portB)

            try {
                val (code1, _) = engA.startPairingCodeSession()
                val wrong = if (code1 == "000000") "999999" else "000000"
                repeat(5) {
                    var failed = false
                    try { engB.pairWithHost("127.0.0.1", portA, wrong) } catch (_: Exception) { failed = true }
                    assertTrue(failed)
                }
                var locked = false
                try { engB.pairWithHost("127.0.0.1", portA, code1) } catch (_: Exception) { locked = true }
                assertTrue(locked)

                val (code2, _) = engA.startPairingCodeSession()
                engB.start()
                engB.pairWithHost("127.0.0.1", portA, code2)
                assertEquals(1, engA.pairedPeers().size)

                val clipLatch = CountDownLatch(1)
                var gotText = ""
                engB.onTextReceived = { t, _ -> gotText = t; clipLatch.countDown() }
                engA.sendText("安卓加密剪贴板测试😀")
                assertTrue(clipLatch.await(3, TimeUnit.SECONDS))
                assertEquals("安卓加密剪贴板测试😀", gotText)

                val srcFile = File(tmp, "照片测试.jpg")
                val payload = LanClipCrypto.randomBytes(600_000)
                srcFile.writeBytes(payload)

                val (saved1, _) = engA.sendFile(srcFile)
                assertEquals("照片测试.jpg", saved1)
                assertArrayEquals(payload, File(dlB, saved1).readBytes())

                val (saved2, _) = engA.sendFile(srcFile)
                assertEquals("照片测试 (1).jpg", saved2)

                engB.setReceiverEnabled(false)
                Thread.sleep(60)
                var refused = false
                try { engA.sendText("should fail") } catch (_: Exception) { refused = true }
                assertTrue(refused)

                engB.setReceiverEnabled(true)
                engA.sendText("ok again")
            } finally {
                engA.shutdown()
                engB.shutdown()
            }
        } finally {
            tmp.deleteRecursively()
        }
    }
}
