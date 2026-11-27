import AppKit
import Network
import Foundation

// MARK: - Translucent HUD Toast

final class ToastHUD {
    static let shared = ToastHUD()
    private var panel: NSPanel?
    private var dismissWork: DispatchWorkItem?

    func show(_ text: String, playSound: Bool = true) {
        DispatchQueue.main.async {
            self.dismissWork?.cancel()
            self.panel?.orderOut(nil)

            if playSound {
                NSSound(named: "Pop")?.play()
            }

            let label = NSTextField(labelWithString: text)
            label.font = NSFont.systemFont(ofSize: 14, weight: .medium)
            label.textColor = .white
            label.alignment = .center
            label.sizeToFit()

            let width = max(260, label.frame.width + 44)
            let height: CGFloat = 44

            let screenFrame = NSScreen.main?.visibleFrame ?? NSRect(x: 0, y: 0, width: 1200, height: 800)
            let originX = screenFrame.midX - width / 2
            let originY = screenFrame.maxY - height - 28

            let p = NSPanel(
                contentRect: NSRect(x: originX, y: originY, width: width, height: height),
                styleMask: [.borderless, .nonactivatingPanel],
                backing: .buffered,
                defer: false
            )
            p.level = .floating
            p.isOpaque = false
            p.backgroundColor = .clear
            p.hasShadow = true
            p.ignoresMouseEvents = true
            p.collectionBehavior = [.canJoinAllSpaces, .transient]

            let bg = NSView(frame: NSRect(x: 0, y: 0, width: width, height: height))
            bg.wantsLayer = true
            bg.layer?.backgroundColor = NSColor(white: 0.12, alpha: 0.90).cgColor
            bg.layer?.cornerRadius = 22
            bg.layer?.borderWidth = 0.5
            bg.layer?.borderColor = NSColor(white: 1.0, alpha: 0.18).cgColor

            label.frame = NSRect(x: 16, y: (height - label.frame.height) / 2, width: width - 32, height: label.frame.height)
            bg.addSubview(label)
            p.contentView = bg
            p.orderFrontRegardless()
            self.panel = p

            let work = DispatchWorkItem { [weak self, weak p] in
                p?.orderOut(nil)
                if self?.panel === p {
                    self?.panel = nil
                }
            }
            self.dismissWork = work
            DispatchQueue.main.asyncAfter(deadline: .now() + 2.6, execute: work)
        }
    }
}

// MARK: - Welcome Window

final class WelcomeWindowController: NSWindowController {
    private let onGenerate: () -> Void
    private let onEnter: () -> Void

    init(onGenerate: @escaping () -> Void, onEnter: @escaping () -> Void) {
        self.onGenerate = onGenerate
        self.onEnter = onEnter

        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 245),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        win.title = "局域网快传 · 设备配对"
        win.isReleasedWhenClosed = false
        win.center()
        super.init(window: win)
        setupUI()
    }

    required init?(coder: NSCoder) { fatalError("unused") }

    private func setupUI() {
        guard let content = window?.contentView else { return }

        let titleLabel = NSTextField(labelWithString: "尚未添加信任设备")
        titleLabel.font = NSFont.systemFont(ofSize: 17, weight: .semibold)
        titleLabel.frame = NSRect(x: 28, y: 185, width: 364, height: 26)
        content.addSubview(titleLabel)

        let descLabel = NSTextField(wrappingLabelWithString: "支持 Mac、Windows、安卓端到端加密互传文字与文件，无需开启「远程登录」。\n让一台设备生成 6 位验证码，另一台输入即可双向打通。")
        descLabel.font = NSFont.systemFont(ofSize: 13)
        descLabel.textColor = .secondaryLabelColor
        descLabel.frame = NSRect(x: 28, y: 125, width: 364, height: 48)
        content.addSubview(descLabel)

        let genBtn = NSButton(title: "我是接收方 · 生成 6 位验证码", target: self, action: #selector(handleGenerate))
        genBtn.bezelStyle = .rounded
        genBtn.controlSize = .large
        genBtn.keyEquivalent = "\r"
        genBtn.frame = NSRect(x: 28, y: 68, width: 364, height: 38)
        content.addSubview(genBtn)

        let enterBtn = NSButton(title: "我是输入方 · 输入对方验证码配对", target: self, action: #selector(handleEnter))
        enterBtn.bezelStyle = .rounded
        enterBtn.controlSize = .large
        enterBtn.frame = NSRect(x: 28, y: 24, width: 364, height: 36)
        content.addSubview(enterBtn)
    }

    @objc private func handleGenerate() {
        window?.close()
        onGenerate()
    }

    @objc private func handleEnter() {
        window?.close()
        onEnter()
    }
}

// MARK: - Generate Code Window

final class GenerateCodeWindowController: NSWindowController, NSWindowDelegate {
    private let engine: LanClipEngine
    private var codeLabel: NSTextField!
    private var timerLabel: NSTextField!
    private var ipLabel: NSTextField!
    private var countdownTimer: Timer?
    private var expiresAt: Date = Date()

    init(engine: LanClipEngine) {
        self.engine = engine
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 400, height: 255),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        win.title = "生成配对验证码"
        win.isReleasedWhenClosed = false
        win.center()
        super.init(window: win)
        win.delegate = self
        setupUI()
    }

    required init?(coder: NSCoder) { fatalError("unused") }

    private func setupUI() {
        guard let content = window?.contentView else { return }

        let tip = NSTextField(labelWithString: "请在另一台 Mac / Windows / 安卓设备上输入下方 6 位验证码：")
        tip.font = NSFont.systemFont(ofSize: 13)
        tip.alignment = .center
        tip.frame = NSRect(x: 16, y: 205, width: 368, height: 22)
        content.addSubview(tip)

        codeLabel = NSTextField(labelWithString: "--- ---")
        codeLabel.font = NSFont.monospacedDigitSystemFont(ofSize: 44, weight: .bold)
        codeLabel.alignment = .center
        codeLabel.textColor = .controlAccentColor
        codeLabel.isSelectable = true
        codeLabel.frame = NSRect(x: 20, y: 130, width: 360, height: 60)
        content.addSubview(codeLabel)

        timerLabel = NSTextField(labelWithString: "有效期：180 秒（单次有效）")
        timerLabel.font = NSFont.systemFont(ofSize: 13)
        timerLabel.textColor = .secondaryLabelColor
        timerLabel.alignment = .center
        timerLabel.frame = NSRect(x: 20, y: 98, width: 360, height: 22)
        content.addSubview(timerLabel)

        let ip = detectLocalLANIP()
        let ipText = ip.isEmpty ? "当前未检测到局域网 IP，请检查 Wi-Fi" : "本机局域网参考 IP：\(ip)（备用直连用）"
        ipLabel = NSTextField(labelWithString: ipText)
        ipLabel.font = NSFont.systemFont(ofSize: 11)
        ipLabel.textColor = .tertiaryLabelColor
        ipLabel.alignment = .center
        ipLabel.frame = NSRect(x: 20, y: 68, width: 360, height: 18)
        content.addSubview(ipLabel)

        let regenBtn = NSButton(title: "重新生成验证码", target: self, action: #selector(regenerate))
        regenBtn.bezelStyle = .rounded
        regenBtn.frame = NSRect(x: 130, y: 20, width: 140, height: 32)
        content.addSubview(regenBtn)
    }

    func showAndStart() {
        NSApp.activate(ignoringOtherApps: true)
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        regenerate()
    }

    @objc private func regenerate() {
        let ip = detectLocalLANIP()
        ipLabel.stringValue = ip.isEmpty ? "当前未检测到局域网 IP，请检查 Wi-Fi" : "本机局域网参考 IP：\(ip)（备用直连用）"
        engine.startPairingCodeSession { [weak self] code, exp in
            guard let self = self else { return }
            let left = String(code.prefix(3))
            let right = String(code.suffix(3))
            self.codeLabel.stringValue = "\(left) \(right)"
            self.expiresAt = exp
            self.startCountdown()
        }
    }

    private func startCountdown() {
        countdownTimer?.invalidate()
        updateCountdownText()
        countdownTimer = Timer.scheduledTimer(withTimeInterval: 1.0, repeats: true) { [weak self] _ in
            self?.updateCountdownText()
        }
    }

    private func updateCountdownText() {
        let secs = Int(ceil(expiresAt.timeIntervalSinceNow))
        if secs <= 0 {
            countdownTimer?.invalidate()
            codeLabel.stringValue = "已过期"
            timerLabel.stringValue = "验证码已过期，请点击下方重新生成"
        } else {
            timerLabel.stringValue = "剩余有效时间：\(secs) 秒（单次有效，最多试错 5 次）"
        }
    }

    func handlePairedSuccess() {
        countdownTimer?.invalidate()
        window?.close()
    }

    func windowWillClose(_ notification: Notification) {
        countdownTimer?.invalidate()
        engine.cancelPairingCodeSession()
    }
}

// MARK: - Enter Code Window

final class EnterCodeWindowController: NSWindowController, NSWindowDelegate {
    private let engine: LanClipEngine
    private var peerPopup: NSPopUpButton!
    private var manualIPField: NSTextField!
    private var codeField: NSTextField!
    private var statusLabel: NSTextField!
    private var pairBtn: NSButton!
    private var peers: [DiscoveredPeer] = []

    init(engine: LanClipEngine) {
        self.engine = engine
        let win = NSWindow(
            contentRect: NSRect(x: 0, y: 0, width: 420, height: 270),
            styleMask: [.titled, .closable],
            backing: .buffered,
            defer: false
        )
        win.title = "输入对方验证码配对"
        win.isReleasedWhenClosed = false
        win.center()
        super.init(window: win)
        win.delegate = self
        setupUI()
    }

    required init?(coder: NSCoder) { fatalError("unused") }

    private func setupUI() {
        guard let content = window?.contentView else { return }

        let l1 = NSTextField(labelWithString: "1. 选择附近的设备：")
        l1.font = NSFont.systemFont(ofSize: 13, weight: .medium)
        l1.frame = NSRect(x: 24, y: 222, width: 372, height: 20)
        content.addSubview(l1)

        peerPopup = NSPopUpButton(frame: NSRect(x: 24, y: 188, width: 372, height: 28), pullsDown: false)
        peerPopup.target = self
        peerPopup.action = #selector(peerChanged)
        content.addSubview(peerPopup)

        let l2 = NSTextField(labelWithString: "手动 IP（仅当列表未搜到时填写）：")
        l2.font = NSFont.systemFont(ofSize: 12)
        l2.textColor = .secondaryLabelColor
        l2.frame = NSRect(x: 24, y: 156, width: 210, height: 20)
        content.addSubview(l2)

        manualIPField = NSTextField(frame: NSRect(x: 238, y: 154, width: 158, height: 24))
        manualIPField.placeholderString = "例如 192.168.1.105"
        content.addSubview(manualIPField)

        let l3 = NSTextField(labelWithString: "2. 输入对方显示的 6 位数字验证码：")
        l3.font = NSFont.systemFont(ofSize: 13, weight: .medium)
        l3.frame = NSRect(x: 24, y: 114, width: 372, height: 20)
        content.addSubview(l3)

        codeField = NSTextField(frame: NSRect(x: 24, y: 74, width: 220, height: 34))
        codeField.font = NSFont.monospacedDigitSystemFont(ofSize: 22, weight: .bold)
        codeField.alignment = .center
        codeField.placeholderString = "6 位数字"
        content.addSubview(codeField)

        pairBtn = NSButton(title: "立即配对", target: self, action: #selector(doPair))
        pairBtn.bezelStyle = .rounded
        pairBtn.keyEquivalent = "\r"
        pairBtn.frame = NSRect(x: 256, y: 74, width: 140, height: 34)
        content.addSubview(pairBtn)

        statusLabel = NSTextField(wrappingLabelWithString: "正在自动搜索同一局域网内的设备...")
        statusLabel.font = NSFont.systemFont(ofSize: 12)
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.frame = NSRect(x: 24, y: 18, width: 372, height: 42)
        content.addSubview(statusLabel)
    }

    func showAndDiscover() {
        NSApp.activate(ignoringOtherApps: true)
        codeField.stringValue = ""
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.stringValue = "正在自动搜索同一局域网内的设备..."
        pairBtn.isEnabled = true
        refreshPeerList([])
        showWindow(nil)
        window?.makeKeyAndOrderFront(nil)
        window?.makeFirstResponder(codeField)
        engine.startDiscovery()
    }

    func refreshPeerList(_ list: [DiscoveredPeer]) {
        self.peers = list
        peerPopup.removeAllItems()
        if list.isEmpty {
            peerPopup.addItem(withTitle: "暂未发现附近设备（可下方手填对方局域网 IP）")
            manualIPField.isEnabled = true
        } else {
            for p in list {
                let tag = p.isPairing ? "（正在等待配对）" : ""
                peerPopup.addItem(withTitle: "\(p.displayName)\(tag)")
            }
            peerPopup.addItem(withTitle: "使用下方手动填写的局域网 IP")
            updateManualIPFieldState()
        }
    }

    @objc private func peerChanged() {
        updateManualIPFieldState()
    }

    private func updateManualIPFieldState() {
        let idx = peerPopup.indexOfSelectedItem
        let usingManual = peers.isEmpty || idx >= peers.count
        manualIPField.isEnabled = usingManual
    }

    @objc private func doPair() {
        let cleanCode = codeField.stringValue.filter { $0.isNumber }
        guard cleanCode.count == 6 else {
            statusLabel.textColor = .systemRed
            statusLabel.stringValue = "请输入完整的 6 位数字验证码。"
            return
        }

        let idx = peerPopup.indexOfSelectedItem
        let selectedEndpoint: NWEndpoint? = (!peers.isEmpty && idx >= 0 && idx < peers.count) ? peers[idx].endpoint : nil
        let manualIP = manualIPField.stringValue.trimmingCharacters(in: .whitespacesAndNewlines)

        if selectedEndpoint == nil && manualIP.isEmpty {
            statusLabel.textColor = .systemRed
            statusLabel.stringValue = "未检测到附近设备，请填写对方的局域网 IP。"
            return
        }

        pairBtn.isEnabled = false
        statusLabel.textColor = .secondaryLabelColor
        statusLabel.stringValue = "正在加密验证并双向绑定..."

        engine.pairWithEndpoint(
            endpoint: selectedEndpoint,
            fallbackHost: manualIP,
            fallbackPort: LANCLIP_DEFAULT_PORT,
            code: cleanCode
        ) { [weak self] result in
            guard let self = self else { return }
            self.pairBtn.isEnabled = true
            switch result {
            case .success(let peer):
                self.window?.close()
                ToastHUD.shared.show("已与 \(peer.displayName) 完成双向加密配对")
            case .failure(let err):
                self.statusLabel.textColor = .systemRed
                self.statusLabel.stringValue = err.localizedDescription
            }
        }
    }

    func windowWillClose(_ notification: Notification) {
        engine.stopDiscovery()
    }
}

// MARK: - AppDelegate

final class AppDelegate: NSObject, NSApplicationDelegate, NSMenuDelegate {
    private var engine: LanClipEngine!
    private var statusItem: NSStatusItem!
    private var menu: NSMenu!

    private var statusMenuItem: NSMenuItem!
    private var sendClipMenuItem: NSMenuItem!
    private var sendFileMenuItem: NSMenuItem!
    private var switchPeerMenuItem: NSMenuItem!
    private var switchPeerSubmenu: NSMenu!
    private var managePeerMenuItem: NSMenuItem!
    private var managePeerSubmenu: NSMenu!
    private var toggleReceiverItem: NSMenuItem!
    private var launchAtLoginItem: NSMenuItem!
    private var ipMenuItem: NSMenuItem!

    private lazy var welcomeWC = WelcomeWindowController(
        onGenerate: { [weak self] in self?.openGenerateCode() },
        onEnter: { [weak self] in self?.openEnterCode() }
    )
    private lazy var genCodeWC = GenerateCodeWindowController(engine: engine)
    private lazy var enterCodeWC = EnterCodeWindowController(engine: engine)

    private var hasCompletedLaunch = false

    private let launchAgentLabel = "com.local.lanclip.app"
    private var launchAgentURL: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/LaunchAgents/\(launchAgentLabel).plist")
    }

    func applicationDidFinishLaunching(_ notification: Notification) {
        do {
            engine = try LanClipEngine()
        } catch {
            let alert = NSAlert()
            alert.alertStyle = .critical
            alert.messageText = "无法初始化「局域网快传」"
            alert.informativeText = error.localizedDescription
            alert.runModal()
            NSApp.terminate(nil)
            return
        }

        engine.onStateChanged = { [weak self] in
            self?.refreshMenu()
        }
        engine.onPeersDiscovered = { [weak self] peers in
            self?.enterCodeWC.refreshPeerList(peers)
        }
        engine.onPairingCompleted = { [weak self] peer in
            self?.genCodeWC.handlePairedSuccess()
            self?.refreshMenu()
            ToastHUD.shared.show("已与 \(peer.displayName) 完成双向加密配对")
        }
        engine.onPairingExpired = {
            ToastHUD.shared.show("配对验证码已过期，需要时可重新生成", playSound: false)
        }
        engine.onTextReceived = { text, peerName in
            let pb = NSPasteboard.general
            pb.clearContents()
            pb.setString(text, forType: .string)
            ToastHUD.shared.show("已收到来自 \(peerName) 的 \(text.count) 字，直接 ⌘V 粘贴")
        }
        engine.onFileReceived = { _, savedName, peerName in
            ToastHUD.shared.show("已收到来自 \(peerName) 的文件「\(savedName)」，保存在 下载/LanClip")
        }

        setupStatusBar()
        engine.start()
        refreshMenu()

        DispatchQueue.main.async { [weak self] in
            guard let self = self else { return }
            self.hasCompletedLaunch = true
            if self.engine.pairedPeers().isEmpty {
                NSApp.activate(ignoringOtherApps: true)
                self.welcomeWC.showWindow(nil)
                self.welcomeWC.window?.makeKeyAndOrderFront(nil)
            } else {
                ToastHUD.shared.show("「局域网快传」已在后台就绪（点击图标发文字，拖入文件直接发）", playSound: false)
            }
        }
    }

    func applicationShouldHandleReopen(_ sender: NSApplication, hasVisibleWindows flag: Bool) -> Bool {
        if !hasCompletedLaunch { return false }
        if flag { return true }
        if engine.pairedPeers().isEmpty {
            NSApp.activate(ignoringOtherApps: true)
            welcomeWC.showWindow(nil)
            welcomeWC.window?.makeKeyAndOrderFront(nil)
        } else {
            sendCurrentClipboard()
        }
        return false
    }

    func application(_ sender: NSApplication, open urls: [URL]) {
        guard !urls.isEmpty else { return }
        if engine.pairedPeers().isEmpty {
            NSApp.activate(ignoringOtherApps: true)
            welcomeWC.showWindow(nil)
            welcomeWC.window?.makeKeyAndOrderFront(nil)
            return
        }
        sendFilesSequentially(urls)
    }

    func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
        return false
    }

    func applicationWillTerminate(_ notification: Notification) {
        engine?.shutdown()
    }

    private func setupStatusBar() {
        statusItem = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        if let btn = statusItem.button {
            if let img = NSImage(systemSymbolName: "doc.on.clipboard", accessibilityDescription: "局域网快传") {
                img.isTemplate = true
                btn.image = img
            } else {
                btn.title = "快传"
            }
        }

        menu = NSMenu()
        menu.delegate = self

        statusMenuItem = NSMenuItem(title: "状态：尚未配对", action: nil, keyEquivalent: "")
        statusMenuItem.isEnabled = false
        menu.addItem(statusMenuItem)

        sendClipMenuItem = NSMenuItem(title: "发送当前剪贴板文字", action: #selector(handleSendClick), keyEquivalent: "")
        sendClipMenuItem.target = self
        menu.addItem(sendClipMenuItem)

        sendFileMenuItem = NSMenuItem(title: "发送文件...", action: #selector(handleSendFilesClick), keyEquivalent: "")
        sendFileMenuItem.target = self
        menu.addItem(sendFileMenuItem)

        menu.addItem(NSMenuItem.separator())

        switchPeerSubmenu = NSMenu()
        switchPeerMenuItem = NSMenuItem(title: "切换目标设备", action: nil, keyEquivalent: "")
        switchPeerMenuItem.submenu = switchPeerSubmenu
        menu.addItem(switchPeerMenuItem)

        managePeerSubmenu = NSMenu()
        managePeerMenuItem = NSMenuItem(title: "管理已配对设备", action: nil, keyEquivalent: "")
        managePeerMenuItem.submenu = managePeerSubmenu
        menu.addItem(managePeerMenuItem)

        let openDownloadsItem = NSMenuItem(title: "打开接收文件夹（下载/LanClip）", action: #selector(handleOpenDownloads), keyEquivalent: "")
        openDownloadsItem.target = self
        menu.addItem(openDownloadsItem)

        menu.addItem(NSMenuItem.separator())

        toggleReceiverItem = NSMenuItem(title: "接收开关：已开启（点击关闭）", action: #selector(handleToggleReceiver), keyEquivalent: "")
        toggleReceiverItem.target = self
        menu.addItem(toggleReceiverItem)

        menu.addItem(NSMenuItem.separator())

        let genItem = NSMenuItem(title: "生成 6 位配对验证码...", action: #selector(openGenerateCode), keyEquivalent: "")
        genItem.target = self
        menu.addItem(genItem)

        let enterItem = NSMenuItem(title: "输入对方验证码配对...", action: #selector(openEnterCode), keyEquivalent: "")
        enterItem.target = self
        menu.addItem(enterItem)

        menu.addItem(NSMenuItem.separator())

        launchAtLoginItem = NSMenuItem(title: "开机自动启动", action: #selector(handleToggleLaunchAtLogin), keyEquivalent: "")
        launchAtLoginItem.target = self
        menu.addItem(launchAtLoginItem)

        ipMenuItem = NSMenuItem(title: "本机局域网 IP：检测中...", action: nil, keyEquivalent: "")
        ipMenuItem.isEnabled = false
        menu.addItem(ipMenuItem)

        menu.addItem(NSMenuItem.separator())

        let quitItem = NSMenuItem(title: "退出", action: #selector(handleQuit), keyEquivalent: "q")
        quitItem.target = self
        menu.addItem(quitItem)

        menu.autoenablesItems = false
        statusItem.menu = menu
    }

    func menuNeedsUpdate(_ menu: NSMenu) {
        refreshMenu()
    }

    private func refreshMenu() {
        let peers = engine.pairedPeers()
        let active = engine.activePeer()
        let recvOn = engine.isReceiverEnabled()

        switchPeerSubmenu.removeAllItems()
        managePeerSubmenu.removeAllItems()

        if let active = active, !peers.isEmpty {
            statusMenuItem.title = "目标：\(active.displayName)（共 \(peers.count) 台）"
            sendClipMenuItem.isEnabled = true
            sendFileMenuItem.isEnabled = true
            switchPeerMenuItem.isEnabled = true
            managePeerMenuItem.isEnabled = true
            toggleReceiverItem.isEnabled = true
            toggleReceiverItem.title = recvOn ? "接收开关：已开启（点击关闭）" : "接收开关：已关闭（点击开启）"

            for p in peers {
                let swItem = NSMenuItem(title: p.displayName, action: #selector(handleSelectPeer(_:)), keyEquivalent: "")
                swItem.target = self
                swItem.representedObject = p.deviceID
                swItem.state = (p.deviceID == active.deviceID) ? .on : .off
                switchPeerSubmenu.addItem(swItem)

                let rmItem = NSMenuItem(title: "移除「\(p.displayName)」", action: #selector(handleRemoveOnePeer(_:)), keyEquivalent: "")
                rmItem.target = self
                rmItem.representedObject = p
                managePeerSubmenu.addItem(rmItem)
            }

            managePeerSubmenu.addItem(NSMenuItem.separator())
            let clearAllItem = NSMenuItem(title: "清除全部配对", action: #selector(handleClearPairing), keyEquivalent: "")
            clearAllItem.target = self
            managePeerSubmenu.addItem(clearAllItem)
        } else {
            statusMenuItem.title = "状态：尚未配对"
            sendClipMenuItem.isEnabled = false
            sendFileMenuItem.isEnabled = false
            switchPeerMenuItem.isEnabled = false
            managePeerMenuItem.isEnabled = false
            toggleReceiverItem.isEnabled = false
            toggleReceiverItem.title = "接收开关（配对后可用）"
        }

        launchAtLoginItem.state = FileManager.default.fileExists(atPath: launchAgentURL.path) ? .on : .off
        let ip = detectLocalLANIP()
        ipMenuItem.title = ip.isEmpty ? "本机局域网 IP：未连接局域网" : "本机局域网 IP：\(ip)"
    }

    @objc private func handleSendClick() {
        sendCurrentClipboard()
    }

    @objc private func handleSendFilesClick() {
        NSApp.activate(ignoringOtherApps: true)
        let panel = NSOpenPanel()
        panel.title = "选择要加密发送的文件"
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        if panel.runModal() == .OK, !panel.urls.isEmpty {
            sendFilesSequentially(panel.urls)
        }
    }

    private func sendFilesSequentially(_ urls: [URL], index: Int = 0, sentCount: Int = 0) {
        if index >= urls.count {
            if sentCount > 1, let targetName = engine.activePeer()?.displayName {
                ToastHUD.shared.show("已加密发送 \(sentCount) 个文件到 \(targetName)")
            }
            return
        }
        let url = urls[index]
        engine.sendFile(at: url) { [weak self] result in
            guard let self = self else { return }
            switch result {
            case .success(let (savedName, peerName)):
                if urls.count == 1 {
                    ToastHUD.shared.show("已加密发送文件「\(savedName)」到 \(peerName)")
                }
                self.sendFilesSequentially(urls, index: index + 1, sentCount: sentCount + 1)
            case .failure(let err):
                NSApp.activate(ignoringOtherApps: true)
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = "文件发送未成功（\(url.lastPathComponent)）"
                alert.informativeText = err.localizedDescription
                alert.addButton(withTitle: "好")
                alert.runModal()
            }
        }
    }

    private func sendCurrentClipboard() {
        let text = NSPasteboard.general.string(forType: .string) ?? ""
        if text.isEmpty {
            ToastHUD.shared.show("当前剪贴板里没有可发送的文字", playSound: false)
            return
        }
        engine.sendText(text) { result in
            switch result {
            case .success(let (chars, peerName)):
                ToastHUD.shared.show("已加密发送 \(chars) 字到 \(peerName)，过去直接粘贴即可")
            case .failure(let err):
                NSApp.activate(ignoringOtherApps: true)
                let alert = NSAlert()
                alert.alertStyle = .warning
                alert.messageText = "发送未成功"
                alert.informativeText = err.localizedDescription
                alert.addButton(withTitle: "好")
                alert.runModal()
            }
        }
    }

    @objc private func handleSelectPeer(_ sender: NSMenuItem) {
        guard let id = sender.representedObject as? String else { return }
        engine.setActivePeer(id)
        if let peer = engine.activePeer() {
            ToastHUD.shared.show("已切换发送目标为「\(peer.displayName)」", playSound: false)
        }
    }

    @objc private func handleRemoveOnePeer(_ sender: NSMenuItem) {
        guard let peer = sender.representedObject as? PairedPeer else { return }
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "确认移除设备「\(peer.displayName)」？"
        alert.informativeText = "移除后该设备将无法继续向你发送文字或文件，如需恢复可重新验证码配对。"
        alert.addButton(withTitle: "移除")
        alert.addButton(withTitle: "取消")
        if alert.runModal() == .alertFirstButtonReturn {
            engine.removePeer(peer.deviceID)
            ToastHUD.shared.show("已移除「\(peer.displayName)」", playSound: false)
        }
    }

    @objc private func handleClearPairing() {
        NSApp.activate(ignoringOtherApps: true)
        let alert = NSAlert()
        alert.alertStyle = .informational
        alert.messageText = "确认清除全部配对设备？"
        alert.informativeText = "清除后需要重新用 6 位验证码配对，才能继续互传文字和文件。"
        alert.addButton(withTitle: "清除全部")
        alert.addButton(withTitle: "取消")
        if alert.runModal() == .alertFirstButtonReturn {
            engine.clearPairing()
            ToastHUD.shared.show("已清除全部配对记录", playSound: false)
        }
    }

    @objc private func handleOpenDownloads() {
        let dir = engine.downloadsDirectory()
        try? FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        NSWorkspace.shared.open(dir)
    }

    @objc private func handleToggleReceiver() {
        let next = !engine.isReceiverEnabled()
        engine.setReceiverEnabled(next)
        if next {
            ToastHUD.shared.show("接收已开启，可以接收已配对设备的文字和文件")
        } else {
            ToastHUD.shared.show("接收已关闭，已完全释放监听端口（出门更安心）")
        }
    }

    @objc private func openGenerateCode() {
        genCodeWC.showAndStart()
    }

    @objc private func openEnterCode() {
        enterCodeWC.showAndDiscover()
    }

    @objc private func handleToggleLaunchAtLogin() {
        let fm = FileManager.default
        if fm.fileExists(atPath: launchAgentURL.path) {
            try? fm.removeItem(at: launchAgentURL)
            refreshMenu()
            ToastHUD.shared.show("已关闭开机自动启动", playSound: false)
            return
        }

        guard let execPath = Bundle.main.executablePath else { return }
        let dir = launchAgentURL.deletingLastPathComponent()
        try? fm.createDirectory(at: dir, withIntermediateDirectories: true)
        let plist: [String: Any] = [
            "Label": launchAgentLabel,
            "ProgramArguments": [execPath],
            "RunAtLoad": true,
            "LimitLoadToSessionType": "Aqua"
        ]
        if let data = try? PropertyListSerialization.data(fromPropertyList: plist, format: .xml, options: 0) {
            try? data.write(to: launchAgentURL, options: .atomic)
            refreshMenu()
            ToastHUD.shared.show("已开启开机自动启动", playSound: false)
        }
    }

    @objc private func handleQuit() {
        NSApp.terminate(nil)
    }
}

// MARK: - Entry Point

@main
struct LanClipApp {
    static func main() {
        let app = NSApplication.shared
        app.setActivationPolicy(.regular)
        let delegate = AppDelegate()
        app.delegate = delegate
        app.run()
    }
}
