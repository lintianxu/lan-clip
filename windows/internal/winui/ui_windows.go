//go:build windows

package winui

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/lintianxu/lan-clip/windows/internal/engine"
	"github.com/lintianxu/lan-clip/windows/internal/proto"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	user32   = windows.NewLazySystemDLL("user32.dll")
	shell32  = windows.NewLazySystemDLL("shell32.dll")
	gdi32    = windows.NewLazySystemDLL("gdi32.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	comdlg32 = windows.NewLazySystemDLL("comdlg32.dll")

	pGetModuleHandleW        = kernel32.NewProc("GetModuleHandleW")
	pGlobalAlloc             = kernel32.NewProc("GlobalAlloc")
	pGlobalLock              = kernel32.NewProc("GlobalLock")
	pGlobalUnlock            = kernel32.NewProc("GlobalUnlock")
	pRegisterClassExW        = user32.NewProc("RegisterClassExW")
	pCreateWindowExW         = user32.NewProc("CreateWindowExW")
	pDestroyWindow           = user32.NewProc("DestroyWindow")
	pShowWindow              = user32.NewProc("ShowWindow")
	pUpdateWindow            = user32.NewProc("UpdateWindow")
	pSetForegroundWindow     = user32.NewProc("SetForegroundWindow")
	pDefWindowProcW          = user32.NewProc("DefWindowProcW")
	pGetMessageW             = user32.NewProc("GetMessageW")
	pIsDialogMessageW        = user32.NewProc("IsDialogMessageW")
	pTranslateMessage        = user32.NewProc("TranslateMessage")
	pDispatchMessageW        = user32.NewProc("DispatchMessageW")
	pPostQuitMessage         = user32.NewProc("PostQuitMessage")
	pPostMessageW            = user32.NewProc("PostMessageW")
	pSendMessageW            = user32.NewProc("SendMessageW")
	pSetWindowTextW          = user32.NewProc("SetWindowTextW")
	pGetWindowTextW          = user32.NewProc("GetWindowTextW")
	pEnableWindow            = user32.NewProc("EnableWindow")
	pSetTimer                = user32.NewProc("SetTimer")
	pKillTimer               = user32.NewProc("KillTimer")
	pMessageBoxW             = user32.NewProc("MessageBoxW")
	pCreatePopupMenu         = user32.NewProc("CreatePopupMenu")
	pAppendMenuW             = user32.NewProc("AppendMenuW")
	pDestroyMenu             = user32.NewProc("DestroyMenu")
	pTrackPopupMenu          = user32.NewProc("TrackPopupMenu")
	pGetCursorPos            = user32.NewProc("GetCursorPos")
	pOpenClipboard           = user32.NewProc("OpenClipboard")
	pCloseClipboard          = user32.NewProc("CloseClipboard")
	pEmptyClipboard          = user32.NewProc("EmptyClipboard")
	pGetClipboardData        = user32.NewProc("GetClipboardData")
	pSetClipboardData        = user32.NewProc("SetClipboardData")
	pLoadCursorW             = user32.NewProc("LoadCursorW")
	pCreateIconIndirect      = user32.NewProc("CreateIconIndirect")
	pDestroyIcon             = user32.NewProc("DestroyIcon")
	pGetStockObject          = gdi32.NewProc("GetStockObject")
	pCreateDIBSection        = gdi32.NewProc("CreateDIBSection")
	pCreateBitmap            = gdi32.NewProc("CreateBitmap")
	pDeleteObject            = gdi32.NewProc("DeleteObject")
	pCreateFontW             = gdi32.NewProc("CreateFontW")
	pShellNotifyIconW        = shell32.NewProc("Shell_NotifyIconW")
	pGetOpenFileNameW        = comdlg32.NewProc("GetOpenFileNameW")
)

const (
	wmDestroy     = 0x0002
	wmCommand     = 0x0111
	wmTimer       = 0x0113
	wmLButtonUp   = 0x0202
	wmRButtonUp   = 0x0205
	wmUser        = 0x0400
	wmTray        = wmUser + 1
	wmShowToast   = wmUser + 2
	wmPairDone    = wmUser + 3
	wmPeersUpdate = wmUser + 4
	wmPairErrUI   = wmUser + 5
	wmPairDoneUI  = wmUser + 6

	wsOverlapped  = 0x00000000
	wsCaption     = 0x00C00000
	wsSysMenu     = 0x00080000
	wsVisible     = 0x10000000
	wsChild       = 0x40000000
	wsTabStop     = 0x00010000
	wsVScroll     = 0x00200000
	wsBorder      = 0x00800000
	esCenter      = 0x0001
	esAutoHScroll = 0x0080
	cbsDropDown   = 0x0003
	bsDefPushBtn  = 0x0001
	ssCenter      = 0x0001
	wsExClientEdge = 0x00000200

	swShow      = 5
	defaultGUIFont = 17
	wmSetFont   = 0x0030
	cbResetContent = 0x014B
	cbAddString    = 0x0143
	cbSetCurSel    = 0x014E
	cbGetCurSel    = 0x0147
	cbErr          = ^uintptr(0)

	mfString    = 0x0000
	mfSeparator = 0x0800
	mfGrayed    = 0x0001
	mfChecked   = 0x0008
	mfPopup     = 0x0010
	tpmBottomAlign = 0x0020
	tpmLeftAlign   = 0x0000

	cfUnicodeText = 13
	gmemMoveable  = 0x0002

	nimAdd     = 0x00000000
	nimModify  = 0x00000001
	nimDelete  = 0x00000002
	nifMessage = 0x00000001
	nifIcon    = 0x00000002
	nifTip     = 0x00000004
	nifInfo    = 0x00000010
	niifInfo   = 0x00000001

	ofnAllowMultiSelect = 0x00000200
	ofnExplorer         = 0x00080000
	ofnFileMustExist    = 0x00001000
	ofnNoChangeDir      = 0x00000008

	mbOK          = 0x00000000
	mbYesNo       = 0x00000004
	mbIconWarning = 0x00000030
	mbIconInfo    = 0x00000040
	idYes         = 6

	cmdSendClip      = 1001
	cmdSendFiles     = 1002
	cmdOpenDownloads = 1003
	cmdToggleRecv    = 1004
	cmdGenCode       = 1005
	cmdEnterCode     = 1006
	cmdClearAll      = 1007
	cmdAutostart     = 1008
	cmdQuit          = 1009
	cmdPeerSelectBase = 2000
	cmdPeerRemoveBase = 3000

	ctrlGenCodeBtn  = 4001
	ctrlEnterCodeBtn = 4002
	ctrlRegenBtn    = 4003
	ctrlComboPeers  = 4004
	ctrlManualIP    = 4005
	ctrlCodeInput   = 4006
	ctrlDoPairBtn   = 4007
)

type wndClassExW struct {
	cbSize        uint32
	style         uint32
	lpfnWndProc   uintptr
	cbClsExtra    int32
	cbWndExtra    int32
	hInstance     uintptr
	hIcon         uintptr
	hCursor       uintptr
	hbrBackground uintptr
	lpszMenuName  *uint16
	lpszClassName *uint16
	hIconSm       uintptr
}

type point struct{ x, y int32 }

type msgStruct struct {
	hwnd    uintptr
	message uint32
	wParam  uintptr
	lParam  uintptr
	time    uint32
	pt      point
}

type notifyIconDataW struct {
	cbSize           uint32
	hWnd             uintptr
	uID              uint32
	uFlags           uint32
	uCallbackMessage uint32
	hIcon            uintptr
	szTip            [128]uint16
	dwState          uint32
	dwStateMask      uint32
	szInfo           [256]uint16
	uVersion         uint32
	szInfoTitle      [64]uint16
	dwInfoFlags      uint32
}

type openFileNameW struct {
	lStructSize       uint32
	hwndOwner         uintptr
	hInstance         uintptr
	lpstrFilter       *uint16
	lpstrCustomFilter *uint16
	nMaxCustFilter    uint32
	nFilterIndex      uint32
	lpstrFile         *uint16
	nMaxFile          uint32
	lpstrFileTitle    *uint16
	nMaxFileTitle     uint32
	lpstrInitialDir   *uint16
	lpstrTitle        *uint16
	flags             uint32
	nFileOffset       uint16
	nFileExtension    uint16
	lpstrDefExt       *uint16
	lCustData         uintptr
	lpfnHook          uintptr
	lpTemplateName    *uint16
	pvReserved        uintptr
	dwReserved        uint32
	flagsEx           uint32
}

type bitmapInfoHeader struct {
	biSize          uint32
	biWidth         int32
	biHeight        int32
	biPlanes        uint16
	biBitCount      uint16
	biCompression   uint32
	biSizeImage     uint32
	biXPelsPerMeter int32
	biYPelsPerMeter int32
	biClrUsed       uint32
	biClrImportant  uint32
}

type iconInfo struct {
	fIcon    int32
	xHotspot uint32
	yHotspot uint32
	hbmMask  uintptr
	hbmColor uintptr
}

var (
	appInst uintptr
	appTray *trayApp
)

type trayApp struct {
	eng         *engine.Engine
	hwnd        uintptr
	hIcon       uintptr
	fontNormal  uintptr
	fontCode    uintptr
	fontTitle   uintptr

	welcomeHwnd uintptr
	genHwnd     uintptr
	genCodeLbl  uintptr
	genTimerLbl uintptr
	genIPLbl    uintptr
	genExpires  time.Time

	enterHwnd   uintptr
	enterCombo  uintptr
	enterIPEdit uintptr
	enterCodeEd uintptr
	enterBtn    uintptr
	enterStatus uintptr
	enterPeers  []engine.DiscoveredPeer

	uiMu        sync.Mutex
	toastQueue  []string
	pairErrMsg  string
	pairDonePeer *proto.PairedPeer
}

func u16(s string) *uint16 {
	p, _ := windows.UTF16PtrFromString(s)
	return p
}

func copyUTF16(dst []uint16, s string) {
	u := windows.StringToUTF16(s)
	n := len(u)
	if n > len(dst) {
		n = len(dst)
	}
	copy(dst[:n], u[:n])
	if len(dst) > 0 {
		dst[len(dst)-1] = 0
	}
}

func getWindowText(hwnd uintptr) string {
	buf := make([]uint16, 512)
	pGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	return windows.UTF16ToString(buf)
}

func setWindowText(hwnd uintptr, s string) {
	pSetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(u16(s))))
}

func createTrayIcon() uintptr {
	const sz = 32
	var bmi bitmapInfoHeader
	bmi.biSize = uint32(unsafe.Sizeof(bmi))
	bmi.biWidth = sz
	bmi.biHeight = -sz
	bmi.biPlanes = 1
	bmi.biBitCount = 32

	var bits unsafe.Pointer
	hColor, _, _ := pCreateDIBSection.Call(0, uintptr(unsafe.Pointer(&bmi)), 0, uintptr(unsafe.Pointer(&bits)), 0, 0)
	if hColor == 0 || bits == nil {
		return 0
	}
	defer pDeleteObject.Call(hColor)

	pixels := unsafe.Slice((*uint32)(bits), sz*sz)
	for y := 0; y < sz; y++ {
		for x := 0; x < sz; x++ {
			if x >= 2 && x <= 29 && y >= 2 && y <= 29 {
				// Blue rounded badge with white clipboard outline
				inCorner := (x < 5 || x > 26) && (y < 5 || y > 26)
				if inCorner {
					continue
				}
				c := uint32(0xFF1E7BFF)
				if x >= 9 && x <= 22 && y >= 7 && y <= 25 {
					c = 0xFFFFFFFF
					if x >= 12 && x <= 19 && (y == 13 || y == 17 || y == 21) {
						c = 0xFF1E7BFF
					}
				}
				if x >= 12 && x <= 19 && y >= 5 && y <= 8 {
					c = 0xFFD9EAFF
				}
				pixels[y*sz+x] = c
			}
		}
	}

	hMask, _, _ := pCreateBitmap.Call(sz, sz, 1, 1, 0)
	defer pDeleteObject.Call(hMask)
	ii := iconInfo{fIcon: 1, hbmMask: hMask, hbmColor: hColor}
	hIcon, _, _ := pCreateIconIndirect.Call(uintptr(unsafe.Pointer(&ii)))
	return hIcon
}

func Run(eng *engine.Engine) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	hInst, _, _ := pGetModuleHandleW.Call(0)
	appInst = hInst

	fNorm, _, _ := pGetStockObject.Call(defaultGUIFont)
	fCode, _, _ := pCreateFontW.Call(44, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 0, 0, uintptr(unsafe.Pointer(u16("Consolas"))))
	fTitle, _, _ := pCreateFontW.Call(20, 0, 0, 0, 600, 0, 0, 0, 1, 0, 0, 0, 0, uintptr(unsafe.Pointer(u16("Microsoft YaHei UI"))))

	a := &trayApp{
		eng:        eng,
		hIcon:      createTrayIcon(),
		fontNormal: fNorm,
		fontCode:   fCode,
		fontTitle:  fTitle,
	}
	appTray = a

	hCur, _, _ := pLoadCursorW.Call(0, 32512)
	clsMain := u16("LanClipTrayClass")
	wc := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   syscall.NewCallback(mainWndProc),
		hInstance:     hInst,
		hIcon:         a.hIcon,
		hCursor:       hCur,
		hbrBackground: 16,
		lpszClassName: clsMain,
	}
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wc)))

	clsDlg := u16("LanClipDlgClass")
	wcDlg := wndClassExW{
		cbSize:        uint32(unsafe.Sizeof(wndClassExW{})),
		lpfnWndProc:   syscall.NewCallback(dlgWndProc),
		hInstance:     hInst,
		hIcon:         a.hIcon,
		hCursor:       hCur,
		hbrBackground: 16,
		lpszClassName: clsDlg,
	}
	pRegisterClassExW.Call(uintptr(unsafe.Pointer(&wcDlg)))

	hwnd, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(clsMain)), uintptr(unsafe.Pointer(u16("局域网快传"))), wsOverlapped, 0, 0, 0, 0, 0, 0, hInst, 0)
	a.hwnd = hwnd

	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = hwnd
	nid.uID = 1
	nid.uFlags = nifMessage | nifIcon | nifTip
	nid.uCallbackMessage = wmTray
	nid.hIcon = a.hIcon
	copyUTF16(nid.szTip[:], "局域网快传 (LanClip)")
	pShellNotifyIconW.Call(nimAdd, uintptr(unsafe.Pointer(&nid)))

	eng.OnPeersDiscovered = func(peers []engine.DiscoveredPeer) {
		a.uiMu.Lock()
		a.enterPeers = peers
		a.uiMu.Unlock()
		pPostMessageW.Call(hwnd, wmPeersUpdate, 0, 0)
	}
	eng.OnPairingCompleted = func(peer proto.PairedPeer) {
		a.uiMu.Lock()
		p := peer
		a.pairDonePeer = &p
		a.uiMu.Unlock()
		pPostMessageW.Call(hwnd, wmPairDone, 0, 0)
	}
	eng.OnPairingExpired = func() {
		a.postToast("配对验证码已过期，需要时可重新生成")
	}
	eng.OnTextReceived = func(text, peerName string) {
		_ = setClipboardText(text)
		a.postToast(fmt.Sprintf("已收到来自 %s 的 %d 字，直接 Ctrl+V 粘贴", peerName, len([]rune(text))))
	}
	eng.OnFileReceived = func(_, savedName, peerName string) {
		a.postToast(fmt.Sprintf("已收到来自 %s 的文件「%s」，保存在 下载/LanClip", peerName, savedName))
	}

	eng.Start()
	if len(eng.PairedPeers()) == 0 {
		a.showWelcome()
	} else {
		a.postToast("「局域网快传」已在右下角托盘就绪（左键点击图标即可发送剪贴板）")
	}

	var m msgStruct
	for {
		ret, _, _ := pGetMessageW.Call(uintptr(unsafe.Pointer(&m)), 0, 0, 0)
		if int32(ret) <= 0 {
			break
		}
		if a.enterHwnd != 0 {
			handled, _, _ := pIsDialogMessageW.Call(a.enterHwnd, uintptr(unsafe.Pointer(&m)))
			if handled != 0 {
				continue
			}
		}
		pTranslateMessage.Call(uintptr(unsafe.Pointer(&m)))
		pDispatchMessageW.Call(uintptr(unsafe.Pointer(&m)))
	}

	pShellNotifyIconW.Call(nimDelete, uintptr(unsafe.Pointer(&nid)))
	if a.hIcon != 0 {
		pDestroyIcon.Call(a.hIcon)
	}
	if a.fontCode != 0 {
		pDeleteObject.Call(a.fontCode)
	}
	if a.fontTitle != 0 {
		pDeleteObject.Call(a.fontTitle)
	}
	eng.Shutdown()
	return nil
}

func (a *trayApp) postToast(msg string) {
	a.uiMu.Lock()
	a.toastQueue = append(a.toastQueue, msg)
	a.uiMu.Unlock()
	pPostMessageW.Call(a.hwnd, wmShowToast, 0, 0)
}

func (a *trayApp) showBalloon(msg string) {
	var nid notifyIconDataW
	nid.cbSize = uint32(unsafe.Sizeof(nid))
	nid.hWnd = a.hwnd
	nid.uID = 1
	nid.uFlags = nifInfo
	nid.dwInfoFlags = niifInfo
	copyUTF16(nid.szInfoTitle[:], "局域网快传")
	copyUTF16(nid.szInfo[:], msg)
	pShellNotifyIconW.Call(nimModify, uintptr(unsafe.Pointer(&nid)))
}

func (a *trayApp) showMsgBox(title, msg string, flags uintptr) uintptr {
	r, _, _ := pMessageBoxW.Call(a.hwnd, uintptr(unsafe.Pointer(u16(msg))), uintptr(unsafe.Pointer(u16(title))), flags)
	return r
}

func mainWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	a := appTray
	if a == nil {
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return r
	}
	switch msg {
	case wmTray:
		switch lParam {
		case wmLButtonUp:
			if len(a.eng.PairedPeers()) == 0 {
				a.showWelcome()
			} else {
				a.sendClipboardAsync()
			}
		case wmRButtonUp:
			a.showContextMenu()
		}
	case wmShowToast:
		a.uiMu.Lock()
		q := a.toastQueue
		a.toastQueue = nil
		a.uiMu.Unlock()
		for _, m := range q {
			a.showBalloon(m)
		}
	case wmPairDone:
		a.uiMu.Lock()
		p := a.pairDonePeer
		a.pairDonePeer = nil
		a.uiMu.Unlock()
		if a.genHwnd != 0 {
			pDestroyWindow.Call(a.genHwnd)
			a.genHwnd = 0
		}
		if p != nil {
			a.showBalloon(fmt.Sprintf("已与 %s 完成双向加密配对", p.DisplayName))
		}
	case wmPeersUpdate:
		a.refreshEnterCombo()
	case wmPairErrUI:
		a.uiMu.Lock()
		em := a.pairErrMsg
		a.uiMu.Unlock()
		if a.enterHwnd != 0 {
			pEnableWindow.Call(a.enterBtn, 1)
			setWindowText(a.enterStatus, em)
		}
	case wmPairDoneUI:
		a.uiMu.Lock()
		p := a.pairDonePeer
		a.pairDonePeer = nil
		a.uiMu.Unlock()
		if a.enterHwnd != 0 {
			pDestroyWindow.Call(a.enterHwnd)
			a.enterHwnd = 0
		}
		if p != nil {
			a.showBalloon(fmt.Sprintf("已与 %s 完成双向加密配对", p.DisplayName))
		}
	case wmCommand:
		id := uint16(wParam & 0xffff)
		a.handleMenuCommand(int(id))
	case wmDestroy:
		pPostQuitMessage.Call(0)
	default:
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return r
	}
	return 0
}

func (a *trayApp) showContextMenu() {
	hMenu, _, _ := pCreatePopupMenu.Call()
	defer pDestroyMenu.Call(hMenu)

	peers := a.eng.PairedPeers()
	active := a.eng.ActivePeer()
	recvOn := a.eng.IsReceiverEnabled()

	statusTxt := "状态：尚未配对"
	if active != nil {
		statusTxt = fmt.Sprintf("目标：%s（共 %d 台）", active.DisplayName, len(peers))
	}
	pAppendMenuW.Call(hMenu, mfString|mfGrayed, 0, uintptr(unsafe.Pointer(u16(statusTxt))))

	sendFlags := uintptr(mfString)
	if active == nil {
		sendFlags |= mfGrayed
	}
	pAppendMenuW.Call(hMenu, sendFlags, cmdSendClip, uintptr(unsafe.Pointer(u16("发送当前剪贴板文字"))))
	pAppendMenuW.Call(hMenu, sendFlags, cmdSendFiles, uintptr(unsafe.Pointer(u16("发送文件..."))))
	pAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	if len(peers) > 0 {
		hSwitch, _, _ := pCreatePopupMenu.Call()
		hManage, _, _ := pCreatePopupMenu.Call()
		for i, p := range peers {
			if i >= 50 {
				break
			}
			f := uintptr(mfString)
			if active != nil && p.DeviceID == active.DeviceID {
				f |= mfChecked
			}
			pAppendMenuW.Call(hSwitch, f, uintptr(cmdPeerSelectBase+i), uintptr(unsafe.Pointer(u16(p.DisplayName))))
			pAppendMenuW.Call(hManage, mfString, uintptr(cmdPeerRemoveBase+i), uintptr(unsafe.Pointer(u16("移除「"+p.DisplayName+"」"))))
		}
		pAppendMenuW.Call(hManage, mfSeparator, 0, 0)
		pAppendMenuW.Call(hManage, mfString, cmdClearAll, uintptr(unsafe.Pointer(u16("清除全部配对"))))
		pAppendMenuW.Call(hMenu, mfPopup, hSwitch, uintptr(unsafe.Pointer(u16("切换目标设备"))))
		pAppendMenuW.Call(hMenu, mfPopup, hManage, uintptr(unsafe.Pointer(u16("管理已配对设备"))))
	}

	pAppendMenuW.Call(hMenu, mfString, cmdOpenDownloads, uintptr(unsafe.Pointer(u16("打开接收文件夹（下载\\LanClip）"))))
	pAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	recvTxt := "接收开关（配对后可用）"
	recvFlags := uintptr(mfString | mfGrayed)
	if active != nil {
		recvFlags = mfString
		if recvOn {
			recvTxt = "接收开关：已开启（点击关闭）"
		} else {
			recvTxt = "接收开关：已关闭（点击开启）"
		}
	}
	pAppendMenuW.Call(hMenu, recvFlags, cmdToggleRecv, uintptr(unsafe.Pointer(u16(recvTxt))))
	pAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	pAppendMenuW.Call(hMenu, mfString, cmdGenCode, uintptr(unsafe.Pointer(u16("生成 6 位配对验证码..."))))
	pAppendMenuW.Call(hMenu, mfString, cmdEnterCode, uintptr(unsafe.Pointer(u16("输入对方验证码配对..."))))
	pAppendMenuW.Call(hMenu, mfSeparator, 0, 0)

	autoFlags := uintptr(mfString)
	if isAutostartEnabled() {
		autoFlags |= mfChecked
	}
	pAppendMenuW.Call(hMenu, autoFlags, cmdAutostart, uintptr(unsafe.Pointer(u16("开机自动启动"))))

	ip := proto.DetectLocalLANIP()
	ipTxt := "本机局域网 IP：未连接局域网"
	if ip != "" {
		ipTxt = "本机局域网 IP：" + ip
	}
	pAppendMenuW.Call(hMenu, mfString|mfGrayed, 0, uintptr(unsafe.Pointer(u16(ipTxt))))
	pAppendMenuW.Call(hMenu, mfSeparator, 0, 0)
	pAppendMenuW.Call(hMenu, mfString, cmdQuit, uintptr(unsafe.Pointer(u16("退出"))))

	var pt point
	pGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	pSetForegroundWindow.Call(a.hwnd)
	pTrackPopupMenu.Call(hMenu, tpmBottomAlign|tpmLeftAlign, uintptr(pt.x), uintptr(pt.y), 0, a.hwnd, 0)
}

func (a *trayApp) handleMenuCommand(id int) {
	switch {
	case id == cmdSendClip:
		a.sendClipboardAsync()
	case id == cmdSendFiles:
		a.pickAndSendFiles()
	case id == cmdOpenDownloads:
		dl := a.eng.DownloadsDir()
		_ = exec.Command("explorer.exe", dl).Start()
	case id == cmdToggleRecv:
		next := !a.eng.IsReceiverEnabled()
		a.eng.SetReceiverEnabled(next)
		if next {
			a.showBalloon("接收已开启，可以接收已配对设备的文字和文件")
		} else {
			a.showBalloon("接收已关闭，已完全释放监听端口（出门更安心）")
		}
	case id == cmdGenCode:
		a.showGenerateCode()
	case id == cmdEnterCode:
		a.showEnterCode()
	case id == cmdClearAll:
		if a.showMsgBox("确认清除", "清除全部配对设备后，需要重新使用 6 位验证码配对。", mbYesNo|mbIconInfo) == idYes {
			a.eng.ClearPairing()
			a.showBalloon("已清除全部配对记录")
		}
	case id == cmdAutostart:
		if toggleAutostart() {
			a.showBalloon("已开启开机自动启动")
		} else {
			a.showBalloon("已关闭开机自动启动")
		}
	case id == cmdQuit:
		pDestroyWindow.Call(a.hwnd)
	case id >= cmdPeerSelectBase && id < cmdPeerSelectBase+50:
		peers := a.eng.PairedPeers()
		idx := id - cmdPeerSelectBase
		if idx >= 0 && idx < len(peers) {
			a.eng.SetActivePeer(peers[idx].DeviceID)
			a.showBalloon("已切换目标设备为「" + peers[idx].DisplayName + "」")
		}
	case id >= cmdPeerRemoveBase && id < cmdPeerRemoveBase+50:
		peers := a.eng.PairedPeers()
		idx := id - cmdPeerRemoveBase
		if idx >= 0 && idx < len(peers) {
			p := peers[idx]
			if a.showMsgBox("确认移除", fmt.Sprintf("确认移除设备「%s」？", p.DisplayName), mbYesNo|mbIconInfo) == idYes {
				a.eng.RemovePeer(p.DeviceID)
				a.showBalloon("已移除「" + p.DisplayName + "」")
			}
		}
	}
}

func (a *trayApp) sendClipboardAsync() {
	text, err := getClipboardText()
	if err != nil || text == "" {
		a.showBalloon("当前剪贴板里没有可发送的文字")
		return
	}
	go func() {
		chars, peerName, err := a.eng.SendText(text, "")
		if err != nil {
			a.postToast("发送失败：" + err.Error())
			return
		}
		a.postToast(fmt.Sprintf("已加密发送 %d 字到 %s，过去直接粘贴即可", chars, peerName))
	}()
}

func (a *trayApp) pickAndSendFiles() {
	buf := make([]uint16, 32768)
	var ofn openFileNameW
	ofn.lStructSize = uint32(unsafe.Sizeof(ofn))
	ofn.hwndOwner = a.hwnd
	ofn.lpstrFilter = u16("所有文件 (*.*)\x00*.*\x00\x00")
	ofn.lpstrFile = &buf[0]
	ofn.nMaxFile = uint32(len(buf))
	ofn.lpstrTitle = u16("选择要加密发送的文件")
	ofn.flags = ofnAllowMultiSelect | ofnExplorer | ofnFileMustExist | ofnNoChangeDir

	ret, _, _ := pGetOpenFileNameW.Call(uintptr(unsafe.Pointer(&ofn)))
	if ret == 0 {
		return
	}
	paths := parseMultiFileBuffer(buf)
	if len(paths) == 0 {
		return
	}
	go func() {
		sent := 0
		var lastPeer string
		for _, p := range paths {
			saved, peerName, err := a.eng.SendFile(p, "")
			if err != nil {
				a.postToast("文件发送失败：" + err.Error())
				return
			}
			sent++
			lastPeer = peerName
			if len(paths) == 1 {
				a.postToast(fmt.Sprintf("已加密发送文件「%s」到 %s", saved, peerName))
			}
		}
		if len(paths) > 1 {
			a.postToast(fmt.Sprintf("已加密发送 %d 个文件到 %s", sent, lastPeer))
		}
	}()
}

func parseMultiFileBuffer(buf []uint16) []string {
	var parts []string
	start := 0
	for i := 0; i < len(buf); i++ {
		if buf[i] == 0 {
			if i == start {
				break
			}
			parts = append(parts, windows.UTF16ToString(buf[start:i]))
			start = i + 1
		}
	}
	if len(parts) == 0 {
		return nil
	}
	if len(parts) == 1 {
		return parts
	}
	dir := parts[0]
	out := make([]string, 0, len(parts)-1)
	for _, f := range parts[1:] {
		out = append(out, filepath.Join(dir, f))
	}
	return out
}

// MARK: - Dialog Windows

func (a *trayApp) makeCtrl(cls, text string, style, exStyle uintptr, x, y, w, h int32, id uintptr, parent uintptr, font uintptr) uintptr {
	hw, _, _ := pCreateWindowExW.Call(exStyle, uintptr(unsafe.Pointer(u16(cls))), uintptr(unsafe.Pointer(u16(text))), style, uintptr(x), uintptr(y), uintptr(w), uintptr(h), parent, id, appInst, 0)
	if font != 0 {
		pSendMessageW.Call(hw, wmSetFont, font, 1)
	}
	return hw
}

func (a *trayApp) showWelcome() {
	if a.welcomeHwnd != 0 {
		pSetForegroundWindow.Call(a.welcomeHwnd)
		return
	}
	hw, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(u16("LanClipDlgClass"))), uintptr(unsafe.Pointer(u16("局域网快传 · 设备配对"))), wsOverlapped|wsCaption|wsSysMenu|wsVisible, 220, 220, 440, 250, 0, 0, appInst, 0)
	a.welcomeHwnd = hw
	a.makeCtrl("STATIC", "尚未添加信任设备", wsChild|wsVisible, 0, 24, 18, 380, 28, 0, hw, a.fontTitle)
	a.makeCtrl("STATIC", "支持 Windows / Mac / 安卓端到端加密互传文字与文件，无需开启远程登录。\n让一台设备生成 6 位验证码，另一台输入即可双向打通。", wsChild|wsVisible, 0, 24, 52, 380, 44, 0, hw, a.fontNormal)
	a.makeCtrl("BUTTON", "我是接收方 · 生成 6 位验证码", wsChild|wsVisible|wsTabStop|bsDefPushBtn, 0, 24, 110, 380, 38, ctrlGenCodeBtn, hw, a.fontNormal)
	a.makeCtrl("BUTTON", "我是输入方 · 输入对方验证码配对", wsChild|wsVisible|wsTabStop, 0, 24, 158, 380, 36, ctrlEnterCodeBtn, hw, a.fontNormal)
	pShowWindow.Call(hw, swShow)
	pUpdateWindow.Call(hw)
	pSetForegroundWindow.Call(hw)
}

func (a *trayApp) showGenerateCode() {
	if a.genHwnd != 0 {
		pSetForegroundWindow.Call(a.genHwnd)
		return
	}
	hw, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(u16("LanClipDlgClass"))), uintptr(unsafe.Pointer(u16("生成配对验证码"))), wsOverlapped|wsCaption|wsSysMenu|wsVisible, 240, 240, 420, 260, 0, 0, appInst, 0)
	a.genHwnd = hw
	a.makeCtrl("STATIC", "请在另一台设备上输入下方 6 位验证码：", wsChild|wsVisible|ssCenter, 0, 20, 16, 365, 22, 0, hw, a.fontNormal)
	a.genCodeLbl = a.makeCtrl("STATIC", "--- ---", wsChild|wsVisible|ssCenter, 0, 20, 44, 365, 56, 0, hw, a.fontCode)
	a.genTimerLbl = a.makeCtrl("STATIC", "有效期：180 秒", wsChild|wsVisible|ssCenter, 0, 20, 108, 365, 22, 0, hw, a.fontNormal)
	a.genIPLbl = a.makeCtrl("STATIC", "", wsChild|wsVisible|ssCenter, 0, 20, 134, 365, 20, 0, hw, a.fontNormal)
	a.makeCtrl("BUTTON", "重新生成验证码", wsChild|wsVisible|wsTabStop, 0, 130, 168, 145, 32, ctrlRegenBtn, hw, a.fontNormal)
	a.regenCodeNow()
	pSetTimer.Call(hw, 1, 1000, 0)
	pShowWindow.Call(hw, swShow)
	pUpdateWindow.Call(hw)
	pSetForegroundWindow.Call(hw)
}

func (a *trayApp) regenCodeNow() {
	code, exp, err := a.eng.StartPairingCodeSession()
	if err != nil {
		return
	}
	a.genExpires = exp
	setWindowText(a.genCodeLbl, code[:3]+" "+code[3:])
	ip := proto.DetectLocalLANIP()
	if ip == "" {
		setWindowText(a.genIPLbl, "当前未检测到局域网 IP，请检查网络")
	} else {
		setWindowText(a.genIPLbl, "本机局域网参考 IP："+ip+"（备用直连用）")
	}
	a.updateGenCountdown()
}

func (a *trayApp) updateGenCountdown() {
	if a.genHwnd == 0 {
		return
	}
	secs := int(time.Until(a.genExpires).Seconds())
	if secs <= 0 {
		setWindowText(a.genCodeLbl, "已过期")
		setWindowText(a.genTimerLbl, "验证码已过期，请点击重新生成")
	} else {
		setWindowText(a.genTimerLbl, fmt.Sprintf("剩余有效时间：%d 秒（单次有效，最多试错 5 次）", secs))
	}
}

func (a *trayApp) showEnterCode() {
	if a.enterHwnd != 0 {
		pSetForegroundWindow.Call(a.enterHwnd)
		return
	}
	hw, _, _ := pCreateWindowExW.Call(0, uintptr(unsafe.Pointer(u16("LanClipDlgClass"))), uintptr(unsafe.Pointer(u16("输入对方验证码配对"))), wsOverlapped|wsCaption|wsSysMenu|wsVisible, 240, 240, 440, 285, 0, 0, appInst, 0)
	a.enterHwnd = hw
	a.makeCtrl("STATIC", "1. 选择附近的设备：", wsChild|wsVisible, 0, 20, 16, 385, 20, 0, hw, a.fontNormal)
	a.enterCombo = a.makeCtrl("COMBOBOX", "", wsChild|wsVisible|wsTabStop|cbsDropDown|wsVScroll, 0, 20, 40, 385, 160, ctrlComboPeers, hw, a.fontNormal)
	a.makeCtrl("STATIC", "手动 IP（未搜到时填）：", wsChild|wsVisible, 0, 20, 78, 160, 20, 0, hw, a.fontNormal)
	a.enterIPEdit = a.makeCtrl("EDIT", "", wsChild|wsVisible|wsTabStop|wsBorder|esAutoHScroll, wsExClientEdge, 185, 75, 220, 24, ctrlManualIP, hw, a.fontNormal)
	a.makeCtrl("STATIC", "2. 输入对方显示的 6 位数字验证码：", wsChild|wsVisible, 0, 20, 114, 385, 20, 0, hw, a.fontNormal)
	a.enterCodeEd = a.makeCtrl("EDIT", "", wsChild|wsVisible|wsTabStop|wsBorder|esCenter, wsExClientEdge, 20, 140, 230, 34, ctrlCodeInput, hw, a.fontTitle)
	a.enterBtn = a.makeCtrl("BUTTON", "立即配对", wsChild|wsVisible|wsTabStop|bsDefPushBtn, 0, 265, 140, 140, 34, ctrlDoPairBtn, hw, a.fontNormal)
	a.enterStatus = a.makeCtrl("STATIC", "正在自动搜索同一局域网内的设备...", wsChild|wsVisible, 0, 20, 188, 385, 42, 0, hw, a.fontNormal)

	a.refreshEnterCombo()
	a.eng.StartDiscovery()
	pShowWindow.Call(hw, swShow)
	pUpdateWindow.Call(hw)
	pSetForegroundWindow.Call(hw)
}

func (a *trayApp) refreshEnterCombo() {
	if a.enterHwnd == 0 {
		return
	}
	a.uiMu.Lock()
	peers := a.enterPeers
	a.uiMu.Unlock()
	pSendMessageW.Call(a.enterCombo, cbResetContent, 0, 0)
	if len(peers) == 0 {
		pSendMessageW.Call(a.enterCombo, cbAddString, 0, uintptr(unsafe.Pointer(u16("暂未发现附近设备（可下方手填对方 IP）"))))
		pSendMessageW.Call(a.enterCombo, cbSetCurSel, 0, 0)
		pEnableWindow.Call(a.enterIPEdit, 1)
		return
	}
	for _, p := range peers {
		label := p.DisplayName + " (" + p.Host + ")"
		if p.IsPairing {
			label += " [等待配对]"
		}
		pSendMessageW.Call(a.enterCombo, cbAddString, 0, uintptr(unsafe.Pointer(u16(label))))
	}
	pSendMessageW.Call(a.enterCombo, cbAddString, 0, uintptr(unsafe.Pointer(u16("使用下方手动填写的局域网 IP"))))
	pSendMessageW.Call(a.enterCombo, cbSetCurSel, 0, 0)
}

func dlgWndProc(hwnd uintptr, msg uint32, wParam, lParam uintptr) uintptr {
	a := appTray
	if a == nil {
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return r
	}
	switch msg {
	case wmTimer:
		if hwnd == a.genHwnd {
			a.updateGenCountdown()
		}
	case wmCommand:
		id := int(wParam & 0xffff)
		switch id {
		case ctrlGenCodeBtn:
			pDestroyWindow.Call(hwnd)
			a.welcomeHwnd = 0
			a.showGenerateCode()
		case ctrlEnterCodeBtn:
			pDestroyWindow.Call(hwnd)
			a.welcomeHwnd = 0
			a.showEnterCode()
		case ctrlRegenBtn:
			a.regenCodeNow()
		case ctrlComboPeers:
			idx, _, _ := pSendMessageW.Call(a.enterCombo, cbGetCurSel, 0, 0)
			a.uiMu.Lock()
			pc := len(a.enterPeers)
			a.uiMu.Unlock()
			if pc == 0 || idx == cbErr || int(idx) >= pc {
				pEnableWindow.Call(a.enterIPEdit, 1)
			} else {
				pEnableWindow.Call(a.enterIPEdit, 0)
			}
		case ctrlDoPairBtn:
			code := getWindowText(a.enterCodeEd)
			idx, _, _ := pSendMessageW.Call(a.enterCombo, cbGetCurSel, 0, 0)
			a.uiMu.Lock()
			peers := a.enterPeers
			a.uiMu.Unlock()
			host := strings.TrimSpace(getWindowText(a.enterIPEdit))
			var port uint16 = proto.DefaultPort
			if len(peers) > 0 && idx != cbErr && int(idx) < len(peers) {
				host = peers[int(idx)].Host
				port = peers[int(idx)].Port
			}
			pEnableWindow.Call(a.enterBtn, 0)
			setWindowText(a.enterStatus, "正在加密验证并双向绑定...")
			go func() {
				peer, err := a.eng.PairWithHost(host, port, code)
				a.uiMu.Lock()
				if err != nil {
					a.pairErrMsg = err.Error()
					a.uiMu.Unlock()
					pPostMessageW.Call(a.hwnd, wmPairErrUI, 0, 0)
				} else {
					a.pairDonePeer = &peer
					a.uiMu.Unlock()
					pPostMessageW.Call(a.hwnd, wmPairDoneUI, 0, 0)
				}
			}()
		}
	case wmDestroy:
		if hwnd == a.welcomeHwnd {
			a.welcomeHwnd = 0
		} else if hwnd == a.genHwnd {
			pKillTimer.Call(hwnd, 1)
			a.genHwnd = 0
			a.eng.CancelPairingCodeSession()
		} else if hwnd == a.enterHwnd {
			a.enterHwnd = 0
			a.eng.StopDiscovery()
		}
	default:
		r, _, _ := pDefWindowProcW.Call(hwnd, uintptr(msg), wParam, lParam)
		return r
	}
	return 0
}

// MARK: - Windows Clipboard & Autostart

func getClipboardText() (string, error) {
	r, _, _ := pOpenClipboard.Call(0)
	if r == 0 {
		return "", fmt.Errorf("open clipboard failed")
	}
	defer pCloseClipboard.Call()
	h, _, _ := pGetClipboardData.Call(cfUnicodeText)
	if h == 0 {
		return "", nil
	}
	ptr, _, _ := pGlobalLock.Call(h)
	if ptr == 0 {
		return "", nil
	}
	defer pGlobalUnlock.Call(h)
	var u16slice []uint16
	for i := 0; i < proto.MaxClipBytes; i++ {
		ch := *(*uint16)(unsafe.Pointer(ptr + uintptr(i)*2))
		if ch == 0 {
			break
		}
		u16slice = append(u16slice, ch)
	}
	return windows.UTF16ToString(u16slice), nil
}

func setClipboardText(text string) error {
	r, _, _ := pOpenClipboard.Call(0)
	if r == 0 {
		return fmt.Errorf("open clipboard failed")
	}
	defer pCloseClipboard.Call()
	pEmptyClipboard.Call()
	u := windows.StringToUTF16(text)
	byteLen := len(u) * 2
	h, _, _ := pGlobalAlloc.Call(gmemMoveable, uintptr(byteLen))
	if h == 0 {
		return fmt.Errorf("GlobalAlloc failed")
	}
	ptr, _, _ := pGlobalLock.Call(h)
	if ptr == 0 {
		return fmt.Errorf("GlobalLock failed")
	}
	dst := unsafe.Slice((*uint16)(unsafe.Pointer(ptr)), len(u))
	copy(dst, u)
	pGlobalUnlock.Call(h)
	res, _, _ := pSetClipboardData.Call(cfUnicodeText, h)
	if res == 0 {
		return fmt.Errorf("SetClipboardData failed")
	}
	return nil
}

const runRegPath = `Software\Microsoft\Windows\CurrentVersion\Run`
const runRegName = "LanClip"

func isAutostartEnabled() bool {
	k, err := registry.OpenKey(registry.CURRENT_USER, runRegPath, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	_, _, err = k.GetStringValue(runRegName)
	return err == nil
}

func toggleAutostart() bool {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runRegPath, registry.SET_VALUE|registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	if _, _, err := k.GetStringValue(runRegName); err == nil {
		_ = k.DeleteValue(runRegName)
		return false
	}
	return setAutostartToExe(k)
}

func setAutostartToExe(k registry.Key) bool {
	buf := make([]uint16, 1024)
	n, err := windows.GetModuleFileName(0, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return false
	}
	exePath := windows.UTF16ToString(buf[:n])
	if err := k.SetStringValue(runRegName, `"`+exePath+`"`); err != nil {
		return false
	}
	return true
}
