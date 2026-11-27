package com.local.lanclip.ui

import android.Manifest
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.provider.OpenableColumns
import android.view.LayoutInflater
import android.view.View
import android.widget.ArrayAdapter
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AlertDialog
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.google.android.material.button.MaterialButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.local.lanclip.LanClipApp
import com.local.lanclip.R
import com.local.lanclip.RecentReceivedItem
import com.local.lanclip.core.DiscoveredDevice
import com.local.lanclip.core.LanClipCrypto
import java.io.File
import java.io.FileInputStream
import java.io.FileOutputStream
import java.util.concurrent.Executors

class MainActivity : AppCompatActivity() {
    private val app by lazy { application as LanClipApp }
    private val engine by lazy { app.engine }
    private val mainHandler = Handler(Looper.getMainLooper())
    private val bgPool = Executors.newSingleThreadExecutor()

    private lateinit var tvStatus: TextView
    private lateinit var tvLocalIP: TextView
    private lateinit var switchReceiver: MaterialSwitch
    private lateinit var btnTargetDevice: MaterialButton
    private lateinit var btnManageDevices: MaterialButton
    private lateinit var btnSendClip: MaterialButton
    private lateinit var btnSendFiles: MaterialButton
    private lateinit var etQuickText: TextInputEditText
    private lateinit var btnSendQuickText: MaterialButton
    private lateinit var btnGenCode: MaterialButton
    private lateinit var btnEnterCode: MaterialButton
    private lateinit var recentContainer: LinearLayout
    private lateinit var tvRecentEmpty: TextView

    private var genCodeDialog: AlertDialog? = null

    private val pickFilesLauncher = registerForActivityResult(ActivityResultContracts.OpenMultipleDocuments()) { uris ->
        if (!uris.isNullOrEmpty()) {
            sendSharedUris(uris)
        }
    }

    private val notifPermLauncher = registerForActivityResult(ActivityResultContracts.RequestPermission()) {}

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        bindViews()
        requestNeededPermissions()
        wireCallbacks()
        refreshUI()
        handleIncomingShare(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        handleIncomingShare(intent)
    }

    override fun onResume() {
        super.onResume()
        refreshUI()
    }

    private fun bindViews() {
        tvStatus = findViewById(R.id.tvStatus)
        tvLocalIP = findViewById(R.id.tvLocalIP)
        switchReceiver = findViewById(R.id.switchReceiver)
        btnTargetDevice = findViewById(R.id.btnTargetDevice)
        btnManageDevices = findViewById(R.id.btnManageDevices)
        btnSendClip = findViewById(R.id.btnSendClip)
        btnSendFiles = findViewById(R.id.btnSendFiles)
        etQuickText = findViewById(R.id.etQuickText)
        btnSendQuickText = findViewById(R.id.btnSendQuickText)
        btnGenCode = findViewById(R.id.btnGenCode)
        btnEnterCode = findViewById(R.id.btnEnterCode)
        recentContainer = findViewById(R.id.recentContainer)
        tvRecentEmpty = findViewById(R.id.tvRecentEmpty)

        switchReceiver.setOnCheckedChangeListener { _, isChecked ->
            if (isChecked != engine.isReceiverEnabled()) {
                engine.setReceiverEnabled(isChecked)
                app.syncReceiverService()
                val msg = if (isChecked) "接收已开启" else "接收已关闭（端口已释放）"
                Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
            }
        }

        btnTargetDevice.setOnClickListener { showTargetPicker() }
        btnManageDevices.setOnClickListener { showManagePeersDialog() }
        btnSendClip.setOnClickListener { sendPhoneClipboard() }
        btnSendFiles.setOnClickListener {
            if (engine.pairedPeers().isEmpty()) {
                Toast.makeText(this, "请先用 6 位验证码配对一台电脑", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            pickFilesLauncher.launch(arrayOf("*/*"))
        }
        btnSendQuickText.setOnClickListener {
            val txt = etQuickText.text?.toString() ?: ""
            if (txt.isEmpty()) {
                Toast.makeText(this, "请先输入要发送的文字", Toast.LENGTH_SHORT).show()
                return@setOnClickListener
            }
            sendTextAsync(txt, clearQuickBox = true)
        }
        btnGenCode.setOnClickListener { showGenerateCodeDialog() }
        btnEnterCode.setOnClickListener { showEnterCodeDialog() }
    }

    private fun requestNeededPermissions() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED) {
                notifPermLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
            }
        }
    }

    private fun wireCallbacks() {
        engine.onStateChanged = {
            mainHandler.post {
                app.syncReceiverService()
                refreshUI()
            }
        }
        engine.onPairingCompleted = { peer ->
            mainHandler.post {
                genCodeDialog?.dismiss()
                genCodeDialog = null
                app.syncReceiverService()
                refreshUI()
                Toast.makeText(this, "已与 ${peer.displayName} 完成双向加密配对", Toast.LENGTH_LONG).show()
            }
        }
        engine.onPairingExpired = {
            mainHandler.post {
                Toast.makeText(this, "配对验证码已过期，需要时可重新生成", Toast.LENGTH_SHORT).show()
            }
        }
        engine.onTextReceived = { text, peerName ->
            mainHandler.post {
                val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                cm.setPrimaryClip(ClipData.newPlainText("LanClip", text))
                app.recentItems.add(0, RecentReceivedItem(false, "收到 ${text.length} 字", text, peerName))
                if (app.recentItems.size > 15) app.recentItems.removeAt(app.recentItems.size - 1)
                refreshRecentList()
                Toast.makeText(this, "已收到来自 $peerName 的 ${text.length} 字（已写入剪贴板）", Toast.LENGTH_LONG).show()
            }
        }
        engine.onFileReceived = { savedName, peerName ->
            mainHandler.post {
                app.recentItems.add(0, RecentReceivedItem(true, "文件：$savedName", "已保存至 系统下载/LanClip/$savedName", peerName))
                if (app.recentItems.size > 15) app.recentItems.removeAt(app.recentItems.size - 1)
                refreshRecentList()
                Toast.makeText(this, "已收到来自 $peerName 的文件「$savedName」", Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun refreshUI() {
        val peers = engine.pairedPeers()
        val active = engine.activePeer()
        val ip = LanClipCrypto.detectLocalLANIP()
        tvLocalIP.text = if (ip.isEmpty()) "本机局域网 IP：未连接 Wi-Fi" else "本机局域网 IP：$ip"

        if (active != null && peers.isNotEmpty()) {
            tvStatus.text = "已配对 ${peers.size} 台设备 · 当前目标：${active.displayName}"
            btnTargetDevice.text = "目标：${active.displayName}"
            btnTargetDevice.isEnabled = true
            btnManageDevices.isEnabled = true
            btnSendClip.isEnabled = true
            btnSendFiles.isEnabled = true
            btnSendQuickText.isEnabled = true
            switchReceiver.isEnabled = true
            switchReceiver.isChecked = engine.isReceiverEnabled()
        } else {
            tvStatus.text = "尚未配对 · 请先生成或输入 6 位验证码"
            btnTargetDevice.text = "目标：未配对"
            btnTargetDevice.isEnabled = false
            btnManageDevices.isEnabled = false
            btnSendClip.isEnabled = false
            btnSendFiles.isEnabled = false
            btnSendQuickText.isEnabled = false
            switchReceiver.isEnabled = false
        }
        refreshRecentList()
    }

    private fun refreshRecentList() {
        recentContainer.removeAllViews()
        val items = app.recentItems.toList()
        tvRecentEmpty.visibility = if (items.isEmpty()) View.VISIBLE else View.GONE
        for (item in items) {
            val tv = TextView(this).apply {
                val prefix = if (item.isFile) "[文件] " else "[文字] "
                val preview = if (item.isFile) item.title else item.content.replace('\n', ' ').take(48)
                text = "$prefix$preview  (来自 ${item.fromPeer})"
                textSize = 13f
                setPadding(16, 14, 16, 14)
                setBackgroundResource(android.R.drawable.list_selector_background)
                setOnClickListener {
                    if (!item.isFile) {
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
                        cm.setPrimaryClip(ClipData.newPlainText("LanClip", item.content))
                        Toast.makeText(this@MainActivity, "已重新复制到手机剪贴板", Toast.LENGTH_SHORT).show()
                    } else {
                        Toast.makeText(this@MainActivity, item.content, Toast.LENGTH_LONG).show()
                    }
                }
            }
            recentContainer.addView(tv)
        }
    }

    private fun sendPhoneClipboard() {
        if (engine.pairedPeers().isEmpty()) {
            Toast.makeText(this, "请先用 6 位验证码配对", Toast.LENGTH_SHORT).show()
            return
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
        val clip = cm.primaryClip
        val text = if (clip != null && clip.itemCount > 0) {
            clip.getItemAt(0).coerceToText(this)?.toString() ?: ""
        } else {
            ""
        }
        if (text.isEmpty()) {
            Toast.makeText(this, "手机剪贴板里当前没有文字", Toast.LENGTH_SHORT).show()
            return
        }
        sendTextAsync(text, clearQuickBox = false)
    }

    private fun sendTextAsync(text: String, clearQuickBox: Boolean) {
        bgPool.submit {
            try {
                val (chars, peerName) = engine.sendText(text)
                mainHandler.post {
                    if (clearQuickBox) etQuickText.setText("")
                    Toast.makeText(this, "已加密发送 $chars 字到 $peerName", Toast.LENGTH_SHORT).show()
                }
            } catch (e: Exception) {
                mainHandler.post {
                    AlertDialog.Builder(this)
                        .setTitle("发送未成功")
                        .setMessage(e.message ?: "发送失败")
                        .setPositiveButton("好", null)
                        .show()
                }
            }
        }
    }

    private fun sendSharedUris(uris: List<Uri>) {
        if (engine.pairedPeers().isEmpty()) {
            Toast.makeText(this, "请先配对设备再发送文件", Toast.LENGTH_LONG).show()
            return
        }
        Toast.makeText(this, "正在加密发送 ${uris.size} 个文件...", Toast.LENGTH_SHORT).show()
        bgPool.submit {
            var sent = 0
            var lastPeer = ""
            for (uri in uris) {
                try {
                    val (name, size) = queryNameAndSize(uri)
                    if (size >= 0L) {
                        contentResolver.openInputStream(uri)?.use { ins ->
                            val (saved, peerName) = engine.sendFileStream(name, size, ins)
                            sent++
                            lastPeer = peerName
                            if (uris.size == 1) {
                                mainHandler.post {
                                    Toast.makeText(this, "已加密发送文件「$saved」到 $peerName", Toast.LENGTH_LONG).show()
                                }
                            }
                        } ?: error("无法读取选中文件")
                    } else {
                        val tmp = File(cacheDir, "send_tmp_${System.nanoTime()}")
                        try {
                            contentResolver.openInputStream(uri)?.use { ins ->
                                FileOutputStream(tmp).use { out -> ins.copyTo(out) }
                            } ?: error("无法读取选中文件")
                            FileInputStream(tmp).use { fis ->
                                val (saved, peerName) = engine.sendFileStream(name, tmp.length(), fis)
                                sent++
                                lastPeer = peerName
                                if (uris.size == 1) {
                                    mainHandler.post {
                                        Toast.makeText(this, "已加密发送文件「$saved」到 $peerName", Toast.LENGTH_LONG).show()
                                    }
                                }
                            }
                        } finally {
                            tmp.delete()
                        }
                    }
                } catch (e: Exception) {
                    mainHandler.post {
                        AlertDialog.Builder(this)
                            .setTitle("文件发送未成功")
                            .setMessage(e.message ?: "发送失败")
                            .setPositiveButton("好", null)
                            .show()
                    }
                    return@submit
                }
            }
            if (uris.size > 1 && sent > 1) {
                mainHandler.post {
                    Toast.makeText(this, "已加密发送 $sent 个文件到 $lastPeer", Toast.LENGTH_LONG).show()
                }
            }
        }
    }

    private fun queryNameAndSize(uri: Uri): Pair<String, Long> {
        var name = uri.lastPathSegment ?: "shared_file"
        var size = -1L
        contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)?.use { c ->
            if (c.moveToFirst()) {
                val nIdx = c.getColumnIndex(OpenableColumns.DISPLAY_NAME)
                val sIdx = c.getColumnIndex(OpenableColumns.SIZE)
                if (nIdx >= 0 && !c.isNull(nIdx)) name = c.getString(nIdx)
                if (sIdx >= 0 && !c.isNull(sIdx)) size = c.getLong(sIdx)
            }
        }
        return name to size
    }

    private fun handleIncomingShare(intent: Intent?) {
        if (intent == null) return
        val action = intent.action ?: return
        if (action == Intent.ACTION_SEND) {
            val sharedText = intent.getStringExtra(Intent.EXTRA_TEXT)
            val stream: Uri? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableExtra(Intent.EXTRA_STREAM)
            }
            if (stream != null) {
                sendSharedUris(listOf(stream))
            } else if (!sharedText.isNullOrEmpty()) {
                if (engine.pairedPeers().isEmpty()) {
                    etQuickText.setText(sharedText)
                    Toast.makeText(this, "请先配对设备后再点发送", Toast.LENGTH_LONG).show()
                } else {
                    sendTextAsync(sharedText, clearQuickBox = false)
                }
            }
            intent.action = Intent.ACTION_MAIN
        } else if (action == Intent.ACTION_SEND_MULTIPLE) {
            val streams: ArrayList<Uri>? = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM, Uri::class.java)
            } else {
                @Suppress("DEPRECATION")
                intent.getParcelableArrayListExtra(Intent.EXTRA_STREAM)
            }
            if (!streams.isNullOrEmpty()) {
                sendSharedUris(streams)
            }
            intent.action = Intent.ACTION_MAIN
        }
    }

    private fun showTargetPicker() {
        val peers = engine.pairedPeers()
        if (peers.isEmpty()) return
        val activeID = engine.activePeer()?.deviceID
        val names = peers.map { it.displayName }.toTypedArray()
        val checked = peers.indexOfFirst { it.deviceID == activeID }.coerceAtLeast(0)
        AlertDialog.Builder(this)
            .setTitle("选择默认发送目标")
            .setSingleChoiceItems(names, checked) { dlg, which ->
                engine.setActivePeer(peers[which].deviceID)
                dlg.dismiss()
                refreshUI()
            }
            .setNegativeButton("取消", null)
            .show()
    }

    private fun showManagePeersDialog() {
        val peers = engine.pairedPeers()
        if (peers.isEmpty()) return
        val names = peers.map { "移除「${it.displayName}」" }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("管理已配对设备")
            .setItems(names) { _, idx ->
                val p = peers[idx]
                AlertDialog.Builder(this)
                    .setTitle("确认移除？")
                    .setMessage("移除后「${p.displayName}」将无法继续向此手机发送文字或文件。")
                    .setPositiveButton("移除") { _, _ -> engine.removePeer(p.deviceID) }
                    .setNegativeButton("取消", null)
                    .show()
            }
            .setNeutralButton("清除全部配对") { _, _ ->
                engine.clearPairing()
                app.syncReceiverService()
            }
            .setNegativeButton("关闭", null)
            .show()
    }

    private fun showGenerateCodeDialog() {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_generate_code, null)
        val tvCode = view.findViewById<TextView>(R.id.tvDialogCode)
        val tvTimer = view.findViewById<TextView>(R.id.tvDialogTimer)
        val tvIP = view.findViewById<TextView>(R.id.tvDialogIP)
        val btnRegen = view.findViewById<MaterialButton>(R.id.btnDialogRegen)

        var expiresAtMs = 0L
        var stopped = false

        fun regenerate() {
            val (code, exp) = engine.startPairingCodeSession()
            expiresAtMs = exp
            tvCode.text = "${code.substring(0, 3)} ${code.substring(3)}"
            val ip = LanClipCrypto.detectLocalLANIP()
            tvIP.text = if (ip.isEmpty()) "未检测到 Wi-Fi 局域网 IP" else "本机参考 IP：$ip"
        }

        val tick = object : Runnable {
            override fun run() {
                if (stopped) return
                val secs = ((expiresAtMs - System.currentTimeMillis()) / 1000L).toInt()
                if (secs <= 0) {
                    tvCode.text = "已过期"
                    tvTimer.text = "验证码已过期，请点击重新生成"
                } else {
                    tvTimer.text = "剩余有效时间：$secs 秒（单次有效，最多试错 5 次）"
                    mainHandler.postDelayed(this, 1000)
                }
            }
        }

        btnRegen.setOnClickListener {
            regenerate()
            mainHandler.removeCallbacks(tick)
            mainHandler.post(tick)
        }

        regenerate()
        val dlg = AlertDialog.Builder(this)
            .setTitle("生成配对验证码")
            .setView(view)
            .setNegativeButton("取消") { _, _ -> }
            .create()
        dlg.setOnDismissListener {
            stopped = true
            mainHandler.removeCallbacks(tick)
            engine.cancelPairingCodeSession()
            genCodeDialog = null
        }
        genCodeDialog = dlg
        dlg.show()
        mainHandler.post(tick)
    }

    private fun showEnterCodeDialog() {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_enter_code, null)
        val spinner = view.findViewById<Spinner>(R.id.spinnerPeers)
        val etManualIP = view.findViewById<EditText>(R.id.etManualIP)
        val etCode = view.findViewById<EditText>(R.id.etPairingCode)
        val tvStatus = view.findViewById<TextView>(R.id.tvEnterStatus)
        val btnPair = view.findViewById<MaterialButton>(R.id.btnConfirmPair)

        var discovered = listOf<DiscoveredDevice>()
        fun updateSpinner(list: List<DiscoveredDevice>) {
            val selfID = engine.currentIdentity().deviceID
            discovered = list.filter { it.deviceID != selfID }
            val labels = if (discovered.isEmpty()) {
                listOf("暂未发现附近设备（可下方手填 IP）")
            } else {
                discovered.map {
                    val tag = if (it.isPairing) " [等待配对]" else ""
                    "${it.displayName} (${it.host})$tag"
                } + "使用下方手动填写的局域网 IP"
            }
            spinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_dropdown_item, labels)
        }

        updateSpinner(app.discovery.snapshot())
        app.discovery.onDevicesChanged = { list ->
            engine.updateDiscoveredDevices(list)
            mainHandler.post { updateSpinner(list) }
        }
        app.discovery.startDiscovery()

        val dlg = AlertDialog.Builder(this)
            .setTitle("输入对方验证码配对")
            .setView(view)
            .setNegativeButton("关闭", null)
            .create()

        dlg.setOnDismissListener {
            app.discovery.stopDiscovery()
            app.discovery.onDevicesChanged = { list -> engine.updateDiscoveredDevices(list) }
        }

        btnPair.setOnClickListener {
            val idx = spinner.selectedItemPosition
            var host = etManualIP.text.toString().trim()
            var port = LanClipCrypto.DEFAULT_PORT
            if (discovered.isNotEmpty() && idx in discovered.indices) {
                host = discovered[idx].host
                port = discovered[idx].port
            }
            val code = etCode.text.toString()
            btnPair.isEnabled = false
            tvStatus.text = "正在加密验证并双向绑定..."
            bgPool.submit {
                try {
                    val peer = engine.pairWithHost(host, port, code)
                    mainHandler.post {
                        dlg.dismiss()
                        app.syncReceiverService()
                        refreshUI()
                        Toast.makeText(this, "已与 ${peer.displayName} 完成双向加密配对", Toast.LENGTH_LONG).show()
                    }
                } catch (e: Exception) {
                    mainHandler.post {
                        btnPair.isEnabled = true
                        tvStatus.text = e.message ?: "配对失败"
                    }
                }
            }
        }

        dlg.show()
    }
}
