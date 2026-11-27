package com.local.lanclip

import android.app.Application
import android.content.ContentValues
import android.content.Context
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.provider.MediaStore
import android.webkit.MimeTypeMap
import com.local.lanclip.core.DirectoryFileReceiveSink
import com.local.lanclip.core.FileReceiveSink
import com.local.lanclip.core.FileWriteSession
import com.local.lanclip.core.LanClipCrypto
import com.local.lanclip.core.LanClipEngine
import com.local.lanclip.core.StateStore
import com.local.lanclip.service.LanDiscovery
import com.local.lanclip.service.ReceiverService
import java.io.File
import java.io.OutputStream
import java.util.concurrent.CopyOnWriteArrayList

data class RecentReceivedItem(
    val isFile: Boolean,
    val title: String,
    val content: String,
    val fromPeer: String,
    val timestampMs: Long = System.currentTimeMillis()
)

class AndroidFileReceiveSink(private val context: Context) : FileReceiveSink {
    private val legacySink by lazy {
        val dir = File(
            Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS),
            "LanClip"
        )
        DirectoryFileReceiveSink(dir)
    }

    override fun openSession(sanitizedName: String, expectedSize: Long): FileWriteSession {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            return legacySink.openSession(sanitizedName, expectedSize)
        }
        val resolver = context.contentResolver
        val ext = sanitizedName.substringAfterLast('.', "").lowercase()
        val mime = if (ext.isNotEmpty()) {
            MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "application/octet-stream"
        } else {
            "application/octet-stream"
        }
        val cv = ContentValues().apply {
            put(MediaStore.Downloads.DISPLAY_NAME, sanitizedName)
            put(MediaStore.Downloads.MIME_TYPE, mime)
            put(MediaStore.Downloads.RELATIVE_PATH, Environment.DIRECTORY_DOWNLOADS + "/LanClip")
            put(MediaStore.Downloads.IS_PENDING, 1)
        }
        val uri: Uri = resolver.insert(MediaStore.Downloads.EXTERNAL_CONTENT_URI, cv)
            ?: throw IllegalStateException("无法在下载目录创建文件")
        val os: OutputStream = resolver.openOutputStream(uri)
            ?: run {
                resolver.delete(uri, null, null)
                throw IllegalStateException("无法写入下载目录")
            }

        return object : FileWriteSession {
            override fun write(bytes: ByteArray, length: Int) {
                os.write(bytes, 0, length)
            }

            override fun commit(): String {
                os.flush()
                os.close()
                val done = ContentValues().apply {
                    put(MediaStore.Downloads.IS_PENDING, 0)
                }
                resolver.update(uri, done, null, null)
                var finalName = sanitizedName
                resolver.query(uri, arrayOf(MediaStore.Downloads.DISPLAY_NAME), null, null, null)?.use { c ->
                    if (c.moveToFirst()) {
                        finalName = c.getString(0) ?: sanitizedName
                    }
                }
                return finalName
            }

            override fun abort() {
                try { os.close() } catch (_: Exception) {}
                try { resolver.delete(uri, null, null) } catch (_: Exception) {}
            }
        }
    }
}

class LanClipApp : Application() {
    lateinit var discovery: LanDiscovery
        private set
    lateinit var engine: LanClipEngine
        private set

    val recentItems = CopyOnWriteArrayList<RecentReceivedItem>()

    override fun onCreate() {
        super.onCreate()
        discovery = LanDiscovery(this)
        val deviceName = "${Build.MANUFACTURER} ${Build.MODEL}".trim().ifBlank { "Android" }
        val store = StateStore(File(filesDir, "state.json"), deviceName)
        engine = LanClipEngine(
            store = store,
            fileSink = AndroidFileReceiveSink(this),
            preferredPort = LanClipCrypto.DEFAULT_PORT,
            advertiseHook = { active, port, pairing, id, name ->
                discovery.updateAdvertise(active, port, pairing, id, name)
            }
        )
        discovery.onDevicesChanged = { list ->
            engine.updateDiscoveredDevices(list)
        }
        engine.start()
        syncReceiverService()
    }

    fun syncReceiverService() {
        val shouldRun = engine.pairedPeers().isNotEmpty() && engine.isReceiverEnabled()
        ReceiverService.sync(this, shouldRun)
    }
}
