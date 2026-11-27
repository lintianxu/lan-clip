package engine

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/lintianxu/lan-clip/windows/internal/proto"
)

type activePairing struct {
	code           string
	expiresAt      time.Time
	failedAttempts int
	timer          *time.Timer
}

type Engine struct {
	mu               sync.Mutex
	statePath        string
	downloadsDir     string
	preferredPort    uint16
	advertiseMDNS    bool
	state            proto.PersistedState
	listener         net.Listener
	actualPort       uint16
	activePair       *activePairing
	sem              chan struct{}
	mdns             *mdnsService
	stopOnce         sync.Once
	closed           bool

	OnStateChanged     func()
	OnPeersDiscovered  func([]DiscoveredPeer)
	OnPairingCompleted func(proto.PairedPeer)
	OnPairingExpired   func()
	OnTextReceived     func(text string, peerName string)
	OnFileReceived     func(destPath string, savedName string, peerName string)
}

func NewEngine(statePath, downloadsDir, displayName string, preferredPort uint16, advertiseMDNS bool) (*Engine, error) {
	st, err := proto.LoadOrCreateState(statePath, displayName)
	if err != nil {
		return nil, err
	}
	e := &Engine{
		statePath:     statePath,
		downloadsDir:  downloadsDir,
		preferredPort: preferredPort,
		advertiseMDNS: advertiseMDNS,
		state:         st,
		sem:           make(chan struct{}, 4),
		mdns:          newMDNSService(st.Identity.DeviceID, st.Identity.DisplayName),
	}
	return e, nil
}

func (e *Engine) CurrentIdentity() proto.DeviceIdentity {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state.Identity
}

func (e *Engine) PairedPeers() []proto.PairedPeer {
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]proto.PairedPeer, len(e.state.Peers))
	copy(out, e.state.Peers)
	return out
}

func (e *Engine) ActivePeer() *proto.PairedPeer {
	e.mu.Lock()
	defer e.mu.Unlock()
	p := e.activePeerLocked()
	if p == nil {
		return nil
	}
	cp := *p
	return &cp
}

func (e *Engine) activePeerLocked() *proto.PairedPeer {
	for i := range e.state.Peers {
		if e.state.Peers[i].DeviceID == e.state.ActivePeerID {
			return &e.state.Peers[i]
		}
	}
	if len(e.state.Peers) > 0 {
		return &e.state.Peers[0]
	}
	return nil
}

func (e *Engine) findPeerLocked(deviceID string) *proto.PairedPeer {
	for i := range e.state.Peers {
		if e.state.Peers[i].DeviceID == deviceID {
			return &e.state.Peers[i]
		}
	}
	return nil
}

func (e *Engine) upsertPeerLocked(p proto.PairedPeer) {
	for i := range e.state.Peers {
		if e.state.Peers[i].DeviceID == p.DeviceID {
			e.state.Peers[i] = p
			e.state.ActivePeerID = p.DeviceID
			return
		}
	}
	e.state.Peers = append(e.state.Peers, p)
	e.state.ActivePeerID = p.DeviceID
}

func (e *Engine) SetActivePeer(deviceID string) {
	e.mu.Lock()
	for _, p := range e.state.Peers {
		if p.DeviceID == deviceID {
			e.state.ActivePeerID = deviceID
			_ = proto.SaveState(e.state, e.statePath)
			break
		}
	}
	cb := e.OnStateChanged
	e.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (e *Engine) RemovePeer(deviceID string) {
	e.mu.Lock()
	filtered := make([]proto.PairedPeer, 0, len(e.state.Peers))
	for _, p := range e.state.Peers {
		if p.DeviceID != deviceID {
			filtered = append(filtered, p)
		}
	}
	e.state.Peers = filtered
	if e.state.ActivePeerID == deviceID {
		if len(filtered) > 0 {
			e.state.ActivePeerID = filtered[0].DeviceID
		} else {
			e.state.ActivePeerID = ""
		}
	}
	if len(filtered) == 0 {
		e.state.ReceiverEnabled = true
	}
	_ = proto.SaveState(e.state, e.statePath)
	e.syncListenerLocked()
	cb := e.OnStateChanged
	e.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (e *Engine) ClearPairing() {
	e.mu.Lock()
	e.state.Peers = []proto.PairedPeer{}
	e.state.ActivePeerID = ""
	e.state.ReceiverEnabled = true
	_ = proto.SaveState(e.state, e.statePath)
	e.syncListenerLocked()
	cb := e.OnStateChanged
	e.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (e *Engine) IsReceiverEnabled() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.state.ReceiverEnabled
}

func (e *Engine) SetReceiverEnabled(enabled bool) {
	e.mu.Lock()
	e.state.ReceiverEnabled = enabled
	_ = proto.SaveState(e.state, e.statePath)
	e.syncListenerLocked()
	cb := e.OnStateChanged
	e.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (e *Engine) ListeningPort() uint16 {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.actualPort
}

func (e *Engine) DownloadsDir() string {
	return e.downloadsDir
}

func (e *Engine) Start() {
	e.mu.Lock()
	e.syncListenerLocked()
	e.mu.Unlock()
}

func (e *Engine) Shutdown() {
	e.stopOnce.Do(func() {
		e.mu.Lock()
		e.closed = true
		if e.activePair != nil && e.activePair.timer != nil {
			e.activePair.timer.Stop()
		}
		e.activePair = nil
		if e.listener != nil {
			_ = e.listener.Close()
			e.listener = nil
		}
		e.actualPort = 0
		e.mu.Unlock()
		e.mdns.Shutdown()
	})
}

func (e *Engine) StartDiscovery() {
	if !e.advertiseMDNS {
		return
	}
	e.mdns.SetBrowsing(true, e.OnPeersDiscovered)
}

func (e *Engine) StopDiscovery() {
	e.mdns.SetBrowsing(false, nil)
}

func (e *Engine) DiscoveredPeers() []DiscoveredPeer {
	return e.mdns.Snapshot()
}

func (e *Engine) StartPairingCodeSession() (string, time.Time, error) {
	code, err := proto.RandomSixDigitCode()
	if err != nil {
		return "", time.Time{}, err
	}
	exp := time.Now().Add(180 * time.Second)

	e.mu.Lock()
	if e.activePair != nil && e.activePair.timer != nil {
		e.activePair.timer.Stop()
	}
	timer := time.AfterFunc(180*time.Second, func() {
		e.mu.Lock()
		expired := e.activePair != nil && !time.Now().Before(e.activePair.expiresAt)
		if expired {
			e.activePair = nil
			e.syncListenerLocked()
		}
		cbState := e.OnStateChanged
		cbExp := e.OnPairingExpired
		e.mu.Unlock()
		if expired {
			if cbState != nil {
				cbState()
			}
			if cbExp != nil {
				cbExp()
			}
		}
	})
	e.activePair = &activePairing{code: code, expiresAt: exp, timer: timer}
	e.syncListenerLocked()
	cb := e.OnStateChanged
	e.mu.Unlock()
	if cb != nil {
		cb()
	}
	return code, exp, nil
}

func (e *Engine) CancelPairingCodeSession() {
	e.mu.Lock()
	if e.activePair != nil && e.activePair.timer != nil {
		e.activePair.timer.Stop()
	}
	e.activePair = nil
	e.syncListenerLocked()
	cb := e.OnStateChanged
	e.mu.Unlock()
	if cb != nil {
		cb()
	}
}

func (e *Engine) shouldListenLocked() bool {
	if e.closed {
		return false
	}
	if e.activePair != nil {
		return true
	}
	return len(e.state.Peers) > 0 && e.state.ReceiverEnabled
}

func (e *Engine) syncListenerLocked() {
	needed := e.shouldListenLocked()
	if !needed {
		if e.listener != nil {
			_ = e.listener.Close()
			e.listener = nil
		}
		e.actualPort = 0
		if e.advertiseMDNS {
			e.mdns.UpdateAdvertise(false, 0, false)
		}
		return
	}

	if e.listener == nil {
		addr := fmt.Sprintf("0.0.0.0:%d", e.preferredPort)
		ln, err := net.Listen("tcp", addr)
		if err != nil && e.preferredPort != 0 {
			ln, err = net.Listen("tcp", "0.0.0.0:0")
		}
		if err != nil {
			return
		}
		tcpAddr := ln.Addr().(*net.TCPAddr)
		e.listener = ln
		e.actualPort = uint16(tcpAddr.Port)
		go e.acceptLoop(ln)
	}

	if e.advertiseMDNS {
		e.mdns.UpdateAdvertise(true, e.actualPort, e.activePair != nil)
	}
}

func (e *Engine) acceptLoop(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		tcpAddr, ok := conn.RemoteAddr().(*net.TCPAddr)
		if !ok || !proto.IsAllowedIP(tcpAddr.IP) {
			_ = conn.Close()
			continue
		}
		select {
		case e.sem <- struct{}{}:
			go func(c net.Conn, ip string) {
				defer func() {
					_ = c.Close()
					<-e.sem
				}()
				e.handleConn(c, ip)
			}(conn, tcpAddr.IP.String())
		default:
			_ = conn.Close()
		}
	}
}

func (e *Engine) handleConn(conn net.Conn, remoteIP string) {
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	mType, body, err := proto.ReadFrame(conn)
	if err != nil {
		return
	}
	switch mType {
	case proto.MsgPairInit:
		e.handleIncomingPair(conn, body, remoteIP)
	case proto.MsgClipInit:
		e.handleIncomingClip(conn, body, remoteIP)
	case proto.MsgFileInit:
		e.handleIncomingFile(conn, body, remoteIP)
	}
}

func (e *Engine) handleIncomingPair(conn net.Conn, payload []byte, remoteIP string) {
	e.mu.Lock()
	sess := e.activePair
	valid := sess != nil && time.Now().Before(sess.expiresAt) && sess.failedAttempts < 5
	myID := e.state.Identity
	myPort := e.actualPort
	if myPort == 0 {
		myPort = e.preferredPort
	}
	e.mu.Unlock()

	if !valid {
		_ = proto.WriteJSONFrame(conn, proto.MsgPairError, proto.WireErrorMsg{Message: "对方未处于验证码配对状态，或验证码已过期。"})
		return
	}

	var initMsg proto.PairInitMsg
	if err := json.Unmarshal(payload, &initMsg); err != nil || initMsg.BDeviceID == "" || initMsg.BDeviceID == myID.DeviceID {
		_ = proto.WriteJSONFrame(conn, proto.MsgPairError, proto.WireErrorMsg{Message: "配对请求格式无效。"})
		return
	}
	bSignPub, err1 := base64.StdEncoding.DecodeString(initMsg.BSignPubB64)
	bEphPub, err2 := base64.StdEncoding.DecodeString(initMsg.BEphPubB64)
	nonceB, err3 := base64.StdEncoding.DecodeString(initMsg.NonceBB64)
	if err1 != nil || err2 != nil || err3 != nil || len(bSignPub) != ed25519.PublicKeySize || len(bEphPub) != 32 {
		_ = proto.WriteJSONFrame(conn, proto.MsgPairError, proto.WireErrorMsg{Message: "配对请求公钥无效。"})
		return
	}

	myPriv, err := myID.SigningKey()
	if err != nil {
		return
	}
	aSignPub := myPriv.Public().(ed25519.PublicKey)
	aEphPriv, err := proto.X25519Generate()
	if err != nil {
		return
	}
	aEphPub := aEphPriv.PublicKey().Bytes()
	nonceA, err := proto.RandomBytes(16)
	if err != nil {
		return
	}
	salt, err := proto.RandomBytes(16)
	if err != nil {
		return
	}

	chal := proto.PairChallengeMsg{
		ADeviceID:    myID.DeviceID,
		ADisplayName: myID.DisplayName,
		ASignPubB64:  base64.StdEncoding.EncodeToString(aSignPub),
		AEphPubB64:   base64.StdEncoding.EncodeToString(aEphPub),
		NonceAB64:    base64.StdEncoding.EncodeToString(nonceA),
		SaltB64:      base64.StdEncoding.EncodeToString(salt),
		AListenPort:  myPort,
	}
	if err := proto.WriteJSONFrame(conn, proto.MsgPairChallenge, chal); err != nil {
		return
	}

	mType, proofBody, err := proto.ReadFrame(conn)
	if err != nil || mType != proto.MsgPairProofB {
		return
	}
	var proofMsg proto.PairProofMsg
	if err := json.Unmarshal(proofBody, &proofMsg); err != nil {
		return
	}
	proofB, err := base64.StdEncoding.DecodeString(proofMsg.ProofB64)
	if err != nil {
		return
	}

	shared, err := proto.X25519Shared(aEphPriv.Bytes(), bEphPub)
	if err != nil {
		return
	}
	tx := proto.ComputePairTranscript(myID.DeviceID, initMsg.BDeviceID, aSignPub, bSignPub, aEphPub, bEphPub, nonceA, nonceB, salt)

	e.mu.Lock()
	sess = e.activePair
	if sess == nil || !time.Now().Before(sess.expiresAt) || sess.failedAttempts >= 5 {
		e.mu.Unlock()
		_ = proto.WriteJSONFrame(conn, proto.MsgPairError, proto.WireErrorMsg{Message: "验证码已失效，请重新生成。"})
		return
	}
	pwKey := proto.PBKDF2SHA256(sess.code, salt)
	macKey, err := proto.DerivePairMacKey(shared, pwKey, salt)
	if err != nil {
		e.mu.Unlock()
		return
	}

	if !proto.VerifyPairProof(proofB, "PROOF-B", tx, macKey) {
		sess.failedAttempts++
		if sess.failedAttempts >= 5 {
			if sess.timer != nil {
				sess.timer.Stop()
			}
			e.activePair = nil
			e.syncListenerLocked()
			cb := e.OnStateChanged
			e.mu.Unlock()
			if cb != nil {
				cb()
			}
			_ = proto.WriteJSONFrame(conn, proto.MsgPairError, proto.WireErrorMsg{Message: "验证码连续输错 5 次，已锁定失效，请在对方设备重新生成。"})
			return
		}
		left := 5 - sess.failedAttempts
		e.mu.Unlock()
		_ = proto.WriteJSONFrame(conn, proto.MsgPairError, proto.WireErrorMsg{Message: fmt.Sprintf("验证码不正确，还可再试 %d 次。", left)})
		return
	}

	if sess.timer != nil {
		sess.timer.Stop()
	}
	e.activePair = nil

	port := initMsg.BListenPort
	if port == 0 {
		port = proto.DefaultPort
	}
	newPeer := proto.PairedPeer{
		DeviceID:            initMsg.BDeviceID,
		DisplayName:         initMsg.BDisplayName,
		Ed25519PublicKeyB64: initMsg.BSignPubB64,
		LastHost:            remoteIP,
		LastPort:            port,
		PairedAt:            time.Now(),
	}
	e.upsertPeerLocked(newPeer)
	e.state.ReceiverEnabled = true
	_ = proto.SaveState(e.state, e.statePath)
	e.syncListenerLocked()
	cbState := e.OnStateChanged
	cbPair := e.OnPairingCompleted
	e.mu.Unlock()

	proofA := proto.ComputePairProof("PROOF-A", tx, macKey)
	_ = proto.WriteJSONFrame(conn, proto.MsgPairProofA, proto.PairProofMsg{ProofB64: base64.StdEncoding.EncodeToString(proofA)})

	if cbState != nil {
		cbState()
	}
	if cbPair != nil {
		cbPair(newPeer)
	}
}

func (e *Engine) handleIncomingClip(conn net.Conn, payload []byte, remoteIP string) {
	var initMsg proto.ClipInitMsg
	if err := json.Unmarshal(payload, &initMsg); err != nil {
		_ = proto.WriteJSONFrame(conn, proto.MsgClipError, proto.WireErrorMsg{Message: "请求格式无效。"})
		return
	}

	e.mu.Lock()
	enabled := e.state.ReceiverEnabled
	peerPtr := e.findPeerLocked(initMsg.SenderDeviceID)
	var peer proto.PairedPeer
	if peerPtr != nil {
		peer = *peerPtr
	}
	myID := e.state.Identity
	e.mu.Unlock()

	if !enabled || peerPtr == nil {
		_ = proto.WriteJSONFrame(conn, proto.MsgClipError, proto.WireErrorMsg{Message: "接收方未开启接收或发送方未在信任列表。"})
		return
	}

	ephPubA, err1 := base64.StdEncoding.DecodeString(initMsg.EphPubAB64)
	nonceA, err2 := base64.StdEncoding.DecodeString(initMsg.NonceAB64)
	sigA, err3 := base64.StdEncoding.DecodeString(initMsg.SigAB64)
	peerPub, err4 := peer.PublicKey()
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(ephPubA) != 32 {
		_ = proto.WriteJSONFrame(conn, proto.MsgClipError, proto.WireErrorMsg{Message: "身份参数无效。"})
		return
	}

	initSigned := proto.ClipInitSignData(peer.DeviceID, myID.DeviceID, ephPubA, nonceA)
	if !ed25519.Verify(peerPub, initSigned, sigA) {
		_ = proto.WriteJSONFrame(conn, proto.MsgClipError, proto.WireErrorMsg{Message: "对方签名验证未通过，已拒绝连接。"})
		return
	}

	myPriv, err := myID.SigningKey()
	if err != nil {
		return
	}
	ephPrivB, err := proto.X25519Generate()
	if err != nil {
		return
	}
	ephPubB := ephPrivB.PublicKey().Bytes()
	nonceB, err := proto.RandomBytes(16)
	if err != nil {
		return
	}
	chalSigned := proto.ClipChallengeSignData(myID.DeviceID, peer.DeviceID, ephPubA, nonceA, ephPubB, nonceB)
	sigB := ed25519.Sign(myPriv, chalSigned)

	chal := proto.ClipChallengeMsg{
		EphPubBB64: base64.StdEncoding.EncodeToString(ephPubB),
		NonceBB64:  base64.StdEncoding.EncodeToString(nonceB),
		SigBB64:    base64.StdEncoding.EncodeToString(sigB),
	}
	if err := proto.WriteJSONFrame(conn, proto.MsgClipChallenge, chal); err != nil {
		return
	}

	mType, payBody, err := proto.ReadFrame(conn)
	if err != nil || mType != proto.MsgClipPayload {
		return
	}
	var sealed proto.ClipSealedMsg
	if err := json.Unmarshal(payBody, &sealed); err != nil {
		return
	}
	combined, err := base64.StdEncoding.DecodeString(sealed.CombinedB64)
	if err != nil {
		return
	}

	shared, err := proto.X25519Shared(ephPrivB.Bytes(), ephPubA)
	if err != nil {
		return
	}
	tx := proto.ClipTranscriptHash(peer.DeviceID, myID.DeviceID, ephPubA, nonceA, ephPubB, nonceB)
	sessKey, err := proto.DeriveClipSessionKey(shared, tx)
	if err != nil {
		return
	}
	plain, err := proto.OpenClipData(combined, "PAYLOAD", tx, sessKey)
	if err != nil || len(plain) == 0 || len(plain) > proto.MaxClipBytes {
		return
	}

	e.mu.Lock()
	if p := e.findPeerLocked(peer.DeviceID); p != nil && remoteIP != "" && p.LastHost != remoteIP {
		p.LastHost = remoteIP
		_ = proto.SaveState(e.state, e.statePath)
	}
	cb := e.OnTextReceived
	e.mu.Unlock()

	if cb != nil {
		cb(string(plain), peer.DisplayName)
	}

	ackBytes, err := proto.SealClipData([]byte("OK"), "ACK", tx, sessKey)
	if err != nil {
		return
	}
	_ = proto.WriteJSONFrame(conn, proto.MsgClipAck, proto.ClipSealedMsg{CombinedB64: base64.StdEncoding.EncodeToString(ackBytes)})
}

func (e *Engine) handleIncomingFile(conn net.Conn, payload []byte, remoteIP string) {
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	var initMsg proto.ClipInitMsg
	if err := json.Unmarshal(payload, &initMsg); err != nil {
		_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "文件请求格式无效。"})
		return
	}

	e.mu.Lock()
	enabled := e.state.ReceiverEnabled
	peerPtr := e.findPeerLocked(initMsg.SenderDeviceID)
	var peer proto.PairedPeer
	if peerPtr != nil {
		peer = *peerPtr
	}
	myID := e.state.Identity
	e.mu.Unlock()

	if !enabled || peerPtr == nil {
		_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "接收方未开启接收或发送方未在信任列表。"})
		return
	}

	ephPubA, err1 := base64.StdEncoding.DecodeString(initMsg.EphPubAB64)
	nonceA, err2 := base64.StdEncoding.DecodeString(initMsg.NonceAB64)
	sigA, err3 := base64.StdEncoding.DecodeString(initMsg.SigAB64)
	peerPub, err4 := peer.PublicKey()
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(ephPubA) != 32 {
		_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "身份参数无效。"})
		return
	}

	initSigned := proto.FileInitSignData(peer.DeviceID, myID.DeviceID, ephPubA, nonceA)
	if !ed25519.Verify(peerPub, initSigned, sigA) {
		_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "对方签名验证未通过，已拒绝文件传输。"})
		return
	}

	myPriv, err := myID.SigningKey()
	if err != nil {
		return
	}
	ephPrivB, err := proto.X25519Generate()
	if err != nil {
		return
	}
	ephPubB := ephPrivB.PublicKey().Bytes()
	nonceB, err := proto.RandomBytes(16)
	if err != nil {
		return
	}
	chalSigned := proto.FileChallengeSignData(myID.DeviceID, peer.DeviceID, ephPubA, nonceA, ephPubB, nonceB)
	sigB := ed25519.Sign(myPriv, chalSigned)

	shared, err := proto.X25519Shared(ephPrivB.Bytes(), ephPubA)
	if err != nil {
		return
	}
	tx := proto.FileTranscriptHash(peer.DeviceID, myID.DeviceID, ephPubA, nonceA, ephPubB, nonceB)
	sessKey, nonceBase, err := proto.DeriveFileSessionKeys(shared, tx)
	if err != nil {
		return
	}

	chal := proto.ClipChallengeMsg{
		EphPubBB64: base64.StdEncoding.EncodeToString(ephPubB),
		NonceBB64:  base64.StdEncoding.EncodeToString(nonceB),
		SigBB64:    base64.StdEncoding.EncodeToString(sigB),
	}
	if err := proto.WriteJSONFrame(conn, proto.MsgFileChallenge, chal); err != nil {
		return
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	mType, metaBody, err := proto.ReadFrame(conn)
	if err != nil || mType != proto.MsgFileMeta {
		return
	}
	plainMeta, err := proto.OpenFileRaw(metaBody, sessKey, nonceBase, proto.FileSeqMeta, proto.FileAAD("FILE-META", nil, tx))
	if err != nil {
		_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "文件元信息解密失败。"})
		return
	}
	var meta proto.FileMetaMsg
	if err := json.Unmarshal(plainMeta, &meta); err != nil || meta.FileSize < 0 || meta.FileSize > proto.MaxFileBytes || meta.ChunkSize <= 0 || meta.ChunkSize > proto.FileChunkSize {
		_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "文件元信息无效或超出 4 GB 安全上限。"})
		return
	}

	sanitizedName := proto.SanitizeReceivedFileName(meta.FileName)
	if err := os.MkdirAll(e.downloadsDir, 0o755); err != nil {
		_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "无法创建接收目录。"})
		return
	}
	tmpFile, err := os.CreateTemp(e.downloadsDir, ".part.*")
	if err != nil {
		_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "无法创建临时文件。"})
		return
	}
	partPath := tmpFile.Name()
	success := false
	defer func() {
		if !success {
			_ = tmpFile.Close()
			_ = os.Remove(partPath)
		}
	}()

	readyCipher, err := proto.SealFileRaw([]byte("OK"), sessKey, nonceBase, proto.FileSeqReady, proto.FileAAD("FILE-READY", nil, tx))
	if err != nil {
		return
	}
	if err := proto.WriteFrame(conn, proto.MsgFileReady, readyCipher); err != nil {
		return
	}

	hasher := sha256.New()
	var bytesWritten int64
	var expectedChunk uint64 = 1

	for {
		_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
		ft, body, err := proto.ReadFrame(conn)
		if err != nil {
			return
		}
		if ft == proto.MsgFileChunk {
			if len(body) < 24 {
				_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "分片数据格式错误。"})
				return
			}
			idx := binary.BigEndian.Uint64(body[:8])
			if idx != expectedChunk {
				_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "分片序号异常。"})
				return
			}
			chunkPlain, err := proto.OpenFileRaw(body[8:], sessKey, nonceBase, idx, proto.FileAAD("FILE-CHUNK", &idx, tx))
			if err != nil {
				_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "文件分片解密失败。"})
				return
			}
			if len(chunkPlain) > meta.ChunkSize || bytesWritten+int64(len(chunkPlain)) > meta.FileSize {
				_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "接收大小超出声明上限。"})
				return
			}
			if len(chunkPlain) > 0 {
				if _, err := tmpFile.Write(chunkPlain); err != nil {
					return
				}
				_, _ = hasher.Write(chunkPlain)
				bytesWritten += int64(len(chunkPlain))
			}
			expectedChunk++
		} else if ft == proto.MsgFileFinish {
			finPlain, err := proto.OpenFileRaw(body, sessKey, nonceBase, proto.FileSeqFinish, proto.FileAAD("FILE-FINISH", nil, tx))
			if err != nil {
				_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "文件结束帧校验失败。"})
				return
			}
			var fin proto.FileFinishMsg
			if err := json.Unmarshal(finPlain, &fin); err != nil {
				return
			}
			receivedChunks := expectedChunk - 1
			actualHex := hex.EncodeToString(hasher.Sum(nil))
			if bytesWritten != meta.FileSize || receivedChunks != fin.TotalChunks || !proto.ConstantTimeEqualHex(actualHex, fin.SHA256Hex) {
				_ = proto.WriteJSONFrame(conn, proto.MsgFileError, proto.WireErrorMsg{Message: "文件完整性校验未通过。"})
				return
			}
			if err := tmpFile.Sync(); err != nil {
				return
			}
			if err := tmpFile.Close(); err != nil {
				return
			}
			destPath := proto.UniqueDestinationPath(e.downloadsDir, sanitizedName)
			if err := os.Rename(partPath, destPath); err != nil {
				return
			}
			success = true

			e.mu.Lock()
			if p := e.findPeerLocked(peer.DeviceID); p != nil && remoteIP != "" && p.LastHost != remoteIP {
				p.LastHost = remoteIP
				_ = proto.SaveState(e.state, e.statePath)
			}
			cb := e.OnFileReceived
			e.mu.Unlock()

			savedName := filepath.Base(destPath)
			if cb != nil {
				cb(destPath, savedName, peer.DisplayName)
			}
			ackPlain, _ := json.Marshal(proto.FileAckMsg{SavedName: savedName})
			ackCipher, err := proto.SealFileRaw(ackPlain, sessKey, nonceBase, proto.FileSeqAck, proto.FileAAD("FILE-ACK", nil, tx))
			if err == nil {
				_ = proto.WriteFrame(conn, proto.MsgFileAck, ackCipher)
			}
			return
		} else {
			return
		}
	}
}

// Outgoing Pairing

func (e *Engine) PairWithHost(host string, port uint16, code string) (proto.PairedPeer, error) {
	var clean strings.Builder
	for _, r := range code {
		if r >= '0' && r <= '9' {
			clean.WriteRune(r)
		}
	}
	cleanCode := clean.String()
	if len(cleanCode) != 6 {
		return proto.PairedPeer{}, errors.New("请输入完整的 6 位数字验证码。")
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return proto.PairedPeer{}, errors.New("请先选择附近的设备，或填写对方局域网 IP。")
	}
	if port == 0 {
		port = proto.DefaultPort
	}

	e.mu.Lock()
	myID := e.state.Identity
	bPort := e.actualPort
	if bPort == 0 {
		bPort = e.preferredPort
	}
	e.mu.Unlock()

	myPriv, err := myID.SigningKey()
	if err != nil {
		return proto.PairedPeer{}, err
	}
	bSignPub := myPriv.Public().(ed25519.PublicKey)
	bEphPriv, err := proto.X25519Generate()
	if err != nil {
		return proto.PairedPeer{}, err
	}
	bEphPub := bEphPriv.PublicKey().Bytes()
	nonceB, err := proto.RandomBytes(16)
	if err != nil {
		return proto.PairedPeer{}, err
	}

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return proto.PairedPeer{}, errors.New("无法连接到对方设备，请确认两台设备在同一局域网且对方正显示验证码。")
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	initMsg := proto.PairInitMsg{
		BDeviceID:    myID.DeviceID,
		BDisplayName: myID.DisplayName,
		BSignPubB64:  base64.StdEncoding.EncodeToString(bSignPub),
		BEphPubB64:   base64.StdEncoding.EncodeToString(bEphPub),
		NonceBB64:    base64.StdEncoding.EncodeToString(nonceB),
		BListenPort:  bPort,
	}
	if err := proto.WriteJSONFrame(conn, proto.MsgPairInit, initMsg); err != nil {
		return proto.PairedPeer{}, err
	}

	mType, chalBody, err := proto.ReadFrame(conn)
	if err != nil {
		return proto.PairedPeer{}, err
	}
	if mType == proto.MsgPairError {
		var werr proto.WireErrorMsg
		if json.Unmarshal(chalBody, &werr) == nil && werr.Message != "" {
			return proto.PairedPeer{}, errors.New(werr.Message)
		}
		return proto.PairedPeer{}, errors.New("对方拒绝了配对请求。")
	}
	if mType != proto.MsgPairChallenge {
		return proto.PairedPeer{}, errors.New("对方返回了无效的配对响应。")
	}
	var chal proto.PairChallengeMsg
	if err := json.Unmarshal(chalBody, &chal); err != nil {
		return proto.PairedPeer{}, errors.New("对方返回了无效的配对响应。")
	}
	aSignPub, err1 := base64.StdEncoding.DecodeString(chal.ASignPubB64)
	aEphPub, err2 := base64.StdEncoding.DecodeString(chal.AEphPubB64)
	nonceA, err3 := base64.StdEncoding.DecodeString(chal.NonceAB64)
	salt, err4 := base64.StdEncoding.DecodeString(chal.SaltB64)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil || len(aSignPub) != ed25519.PublicKeySize || len(aEphPub) != 32 {
		return proto.PairedPeer{}, errors.New("对方返回的证书参数无效。")
	}

	shared, err := proto.X25519Shared(bEphPriv.Bytes(), aEphPub)
	if err != nil {
		return proto.PairedPeer{}, err
	}
	pwKey := proto.PBKDF2SHA256(cleanCode, salt)
	tx := proto.ComputePairTranscript(chal.ADeviceID, myID.DeviceID, aSignPub, bSignPub, aEphPub, bEphPub, nonceA, nonceB, salt)
	macKey, err := proto.DerivePairMacKey(shared, pwKey, salt)
	if err != nil {
		return proto.PairedPeer{}, err
	}
	proofB := proto.ComputePairProof("PROOF-B", tx, macKey)
	if err := proto.WriteJSONFrame(conn, proto.MsgPairProofB, proto.PairProofMsg{ProofB64: base64.StdEncoding.EncodeToString(proofB)}); err != nil {
		return proto.PairedPeer{}, err
	}

	ackType, ackBody, err := proto.ReadFrame(conn)
	if err != nil {
		return proto.PairedPeer{}, err
	}
	if ackType == proto.MsgPairError {
		var werr proto.WireErrorMsg
		if json.Unmarshal(ackBody, &werr) == nil && werr.Message != "" {
			return proto.PairedPeer{}, errors.New(werr.Message)
		}
		return proto.PairedPeer{}, errors.New("验证码校验失败。")
	}
	if ackType != proto.MsgPairProofA {
		return proto.PairedPeer{}, errors.New("验证码校验未通过。")
	}
	var proofAMsg proto.PairProofMsg
	if err := json.Unmarshal(ackBody, &proofAMsg); err != nil {
		return proto.PairedPeer{}, errors.New("验证码校验未通过。")
	}
	proofA, err := base64.StdEncoding.DecodeString(proofAMsg.ProofB64)
	if err != nil || !proto.VerifyPairProof(proofA, "PROOF-A", tx, macKey) {
		return proto.PairedPeer{}, errors.New("验证码校验未通过，请重新确认。")
	}

	resolvedHost := host
	if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok && ra.IP.To4() != nil {
		resolvedHost = ra.IP.To4().String()
	}
	aPort := chal.AListenPort
	if aPort == 0 {
		aPort = proto.DefaultPort
	}
	newPeer := proto.PairedPeer{
		DeviceID:            chal.ADeviceID,
		DisplayName:         chal.ADisplayName,
		Ed25519PublicKeyB64: chal.ASignPubB64,
		LastHost:            resolvedHost,
		LastPort:            aPort,
		PairedAt:            time.Now(),
	}

	e.mu.Lock()
	e.upsertPeerLocked(newPeer)
	e.state.ReceiverEnabled = true
	errSave := proto.SaveState(e.state, e.statePath)
	e.syncListenerLocked()
	cb := e.OnStateChanged
	e.mu.Unlock()
	if errSave != nil {
		return proto.PairedPeer{}, errSave
	}
	if cb != nil {
		cb()
	}
	return newPeer, nil
}

func (e *Engine) resolveTarget(peerID string) (proto.PairedPeer, string, uint16, error) {
	e.mu.Lock()
	var pPtr *proto.PairedPeer
	if peerID != "" {
		pPtr = e.findPeerLocked(peerID)
	} else {
		pPtr = e.activePeerLocked()
	}
	if pPtr == nil {
		e.mu.Unlock()
		return proto.PairedPeer{}, "", 0, errors.New("尚未完成设备配对，请先用 6 位验证码配对。")
	}
	peer := *pPtr
	e.mu.Unlock()

	for _, d := range e.mdns.Snapshot() {
		if d.DeviceID == peer.DeviceID {
			return peer, d.Host, d.Port, nil
		}
	}
	if peer.LastHost != "" {
		port := peer.LastPort
		if port == 0 {
			port = proto.DefaultPort
		}
		return peer, peer.LastHost, port, nil
	}
	return proto.PairedPeer{}, "", 0, fmt.Errorf("找不到目标设备「%s」的网络地址，请确认对方已开机并连在同一局域网。", peer.DisplayName)
}

func (e *Engine) SendText(text string, peerID string) (int, string, error) {
	utf8Bytes := []byte(text)
	if len(utf8Bytes) == 0 {
		return 0, "", errors.New("当前剪贴板里没有可发送的文字。")
	}
	if len(utf8Bytes) > proto.MaxClipBytes {
		return 0, "", errors.New("剪贴板文字超过 1 MB 安全上限，已取消发送。")
	}
	charCount := len([]rune(text))

	peer, host, port, err := e.resolveTarget(peerID)
	if err != nil {
		return 0, "", err
	}

	e.mu.Lock()
	myID := e.state.Identity
	e.mu.Unlock()

	myPriv, err := myID.SigningKey()
	if err != nil {
		return 0, "", err
	}
	peerPub, err := peer.PublicKey()
	if err != nil {
		return 0, "", err
	}
	ephPrivA, err := proto.X25519Generate()
	if err != nil {
		return 0, "", err
	}
	ephPubA := ephPrivA.PublicKey().Bytes()
	nonceA, err := proto.RandomBytes(16)
	if err != nil {
		return 0, "", err
	}
	sigA := ed25519.Sign(myPriv, proto.ClipInitSignData(myID.DeviceID, peer.DeviceID, ephPubA, nonceA))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 4*time.Second)
	if err != nil {
		return 0, "", errors.New("无法连接对方设备：请确认对方已打开「局域网快传」且接收开关处于开启状态。")
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))

	initMsg := proto.ClipInitMsg{
		SenderDeviceID: myID.DeviceID,
		EphPubAB64:     base64.StdEncoding.EncodeToString(ephPubA),
		NonceAB64:      base64.StdEncoding.EncodeToString(nonceA),
		SigAB64:        base64.StdEncoding.EncodeToString(sigA),
	}
	if err := proto.WriteJSONFrame(conn, proto.MsgClipInit, initMsg); err != nil {
		return 0, "", err
	}

	mType, chalBody, err := proto.ReadFrame(conn)
	if err != nil {
		return 0, "", err
	}
	if mType == proto.MsgClipError {
		var werr proto.WireErrorMsg
		if json.Unmarshal(chalBody, &werr) == nil && werr.Message != "" {
			return 0, "", errors.New(werr.Message)
		}
		return 0, "", errors.New("对方拒绝接收。")
	}
	if mType != proto.MsgClipChallenge {
		return 0, "", errors.New("安全拦截：对方设备响应格式异常。")
	}
	var chal proto.ClipChallengeMsg
	if err := json.Unmarshal(chalBody, &chal); err != nil {
		return 0, "", errors.New("安全拦截：对方设备响应格式异常。")
	}
	ephPubB, err1 := base64.StdEncoding.DecodeString(chal.EphPubBB64)
	nonceB, err2 := base64.StdEncoding.DecodeString(chal.NonceBB64)
	sigB, err3 := base64.StdEncoding.DecodeString(chal.SigBB64)
	if err1 != nil || err2 != nil || err3 != nil || len(ephPubB) != 32 {
		return 0, "", errors.New("安全拦截：对方握手参数异常。")
	}

	expectedChal := proto.ClipChallengeSignData(peer.DeviceID, myID.DeviceID, ephPubA, nonceA, ephPubB, nonceB)
	if !ed25519.Verify(peerPub, expectedChal, sigB) {
		return 0, "", errors.New("安全拦截：对方身份签名校验未通过，已中止发送。")
	}

	shared, err := proto.X25519Shared(ephPrivA.Bytes(), ephPubB)
	if err != nil {
		return 0, "", err
	}
	tx := proto.ClipTranscriptHash(myID.DeviceID, peer.DeviceID, ephPubA, nonceA, ephPubB, nonceB)
	sessKey, err := proto.DeriveClipSessionKey(shared, tx)
	if err != nil {
		return 0, "", err
	}
	sealed, err := proto.SealClipData(utf8Bytes, "PAYLOAD", tx, sessKey)
	if err != nil {
		return 0, "", err
	}
	if err := proto.WriteJSONFrame(conn, proto.MsgClipPayload, proto.ClipSealedMsg{CombinedB64: base64.StdEncoding.EncodeToString(sealed)}); err != nil {
		return 0, "", err
	}

	ackType, ackBody, err := proto.ReadFrame(conn)
	if err != nil || ackType != proto.MsgClipAck {
		return 0, "", errors.New("未能确认对方已接收文字。")
	}
	var ackMsg proto.ClipSealedMsg
	if json.Unmarshal(ackBody, &ackMsg) != nil {
		return 0, "", errors.New("未能确认对方已接收文字。")
	}
	ackBytes, err := base64.StdEncoding.DecodeString(ackMsg.CombinedB64)
	if err != nil {
		return 0, "", errors.New("未能确认对方已接收文字。")
	}
	ackPlain, err := proto.OpenClipData(ackBytes, "ACK", tx, sessKey)
	if err != nil || string(ackPlain) != "OK" {
		return 0, "", errors.New("未能确认对方已接收文字。")
	}
	return charCount, peer.DisplayName, nil
}

func (e *Engine) SendFile(filePath, peerID string) (string, string, error) {
	info, err := os.Stat(filePath)
	if err != nil {
		return "", "", errors.New("无法读取选中的文件。")
	}
	if info.IsDir() {
		return "", "", errors.New("暂不支持直接发送文件夹，请压缩后再发送。")
	}
	fileSize := info.Size()
	if fileSize < 0 || fileSize > proto.MaxFileBytes {
		return "", "", errors.New("文件超过 4 GB 单文件上限，已取消发送。")
	}
	f, err := os.Open(filePath)
	if err != nil {
		return "", "", errors.New("无法打开选中的文件。")
	}
	defer func() { _ = f.Close() }()

	peer, host, port, err := e.resolveTarget(peerID)
	if err != nil {
		return "", "", err
	}

	e.mu.Lock()
	myID := e.state.Identity
	e.mu.Unlock()

	myPriv, err := myID.SigningKey()
	if err != nil {
		return "", "", err
	}
	peerPub, err := peer.PublicKey()
	if err != nil {
		return "", "", err
	}
	ephPrivA, err := proto.X25519Generate()
	if err != nil {
		return "", "", err
	}
	ephPubA := ephPrivA.PublicKey().Bytes()
	nonceA, err := proto.RandomBytes(16)
	if err != nil {
		return "", "", err
	}
	sigA := ed25519.Sign(myPriv, proto.FileInitSignData(myID.DeviceID, peer.DeviceID, ephPubA, nonceA))

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return "", "", errors.New("无法连接对方设备：请确认对方已打开「局域网快传」且接收开关处于开启状态。")
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	initMsg := proto.ClipInitMsg{
		SenderDeviceID: myID.DeviceID,
		EphPubAB64:     base64.StdEncoding.EncodeToString(ephPubA),
		NonceAB64:      base64.StdEncoding.EncodeToString(nonceA),
		SigAB64:        base64.StdEncoding.EncodeToString(sigA),
	}
	if err := proto.WriteJSONFrame(conn, proto.MsgFileInit, initMsg); err != nil {
		return "", "", err
	}

	mType, chalBody, err := proto.ReadFrame(conn)
	if err != nil {
		return "", "", err
	}
	if mType == proto.MsgFileError {
		var werr proto.WireErrorMsg
		if json.Unmarshal(chalBody, &werr) == nil && werr.Message != "" {
			return "", "", errors.New(werr.Message)
		}
		return "", "", errors.New("对方拒绝接收文件。")
	}
	if mType != proto.MsgFileChallenge {
		return "", "", errors.New("安全拦截：对方设备文件握手响应异常。")
	}
	var chal proto.ClipChallengeMsg
	if err := json.Unmarshal(chalBody, &chal); err != nil {
		return "", "", errors.New("安全拦截：对方设备文件握手响应异常。")
	}
	ephPubB, err1 := base64.StdEncoding.DecodeString(chal.EphPubBB64)
	nonceB, err2 := base64.StdEncoding.DecodeString(chal.NonceBB64)
	sigB, err3 := base64.StdEncoding.DecodeString(chal.SigBB64)
	if err1 != nil || err2 != nil || err3 != nil || len(ephPubB) != 32 {
		return "", "", errors.New("安全拦截：对方握手参数异常。")
	}
	expectedChal := proto.FileChallengeSignData(peer.DeviceID, myID.DeviceID, ephPubA, nonceA, ephPubB, nonceB)
	if !ed25519.Verify(peerPub, expectedChal, sigB) {
		return "", "", errors.New("安全拦截：对方身份签名校验未通过，已中止发送文件。")
	}

	shared, err := proto.X25519Shared(ephPrivA.Bytes(), ephPubB)
	if err != nil {
		return "", "", err
	}
	tx := proto.FileTranscriptHash(myID.DeviceID, peer.DeviceID, ephPubA, nonceA, ephPubB, nonceB)
	sessKey, nonceBase, err := proto.DeriveFileSessionKeys(shared, tx)
	if err != nil {
		return "", "", err
	}

	metaBytes, _ := json.Marshal(proto.FileMetaMsg{
		FileName:  filepath.Base(filePath),
		FileSize:  fileSize,
		ChunkSize: proto.FileChunkSize,
	})
	metaCipher, err := proto.SealFileRaw(metaBytes, sessKey, nonceBase, proto.FileSeqMeta, proto.FileAAD("FILE-META", nil, tx))
	if err != nil {
		return "", "", err
	}
	if err := proto.WriteFrame(conn, proto.MsgFileMeta, metaCipher); err != nil {
		return "", "", err
	}

	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	rt, rBody, err := proto.ReadFrame(conn)
	if err != nil {
		return "", "", err
	}
	if rt == proto.MsgFileError {
		var werr proto.WireErrorMsg
		if json.Unmarshal(rBody, &werr) == nil && werr.Message != "" {
			return "", "", errors.New(werr.Message)
		}
		return "", "", errors.New("对方未准备好接收文件。")
	}
	if rt != proto.MsgFileReady {
		return "", "", errors.New("对方未准备好接收文件。")
	}
	readyPlain, err := proto.OpenFileRaw(rBody, sessKey, nonceBase, proto.FileSeqReady, proto.FileAAD("FILE-READY", nil, tx))
	if err != nil || string(readyPlain) != "OK" {
		return "", "", errors.New("对方未准备好接收文件。")
	}

	buf := make([]byte, proto.FileChunkSize)
	hasher := sha256.New()
	var chunkIndex uint64 = 1

	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
			_, _ = hasher.Write(buf[:n])
			cipher, err := proto.SealFileRaw(buf[:n], sessKey, nonceBase, chunkIndex, proto.FileAAD("FILE-CHUNK", &chunkIndex, tx))
			if err != nil {
				return "", "", err
			}
			frameBody := make([]byte, 8+len(cipher))
			binary.BigEndian.PutUint64(frameBody[:8], chunkIndex)
			copy(frameBody[8:], cipher)
			if err := proto.WriteFrame(conn, proto.MsgFileChunk, frameBody); err != nil {
				return "", "", err
			}
			chunkIndex++
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return "", "", readErr
		}
	}

	totalChunks := chunkIndex - 1
	finBytes, _ := json.Marshal(proto.FileFinishMsg{
		SHA256Hex:   hex.EncodeToString(hasher.Sum(nil)),
		TotalChunks: totalChunks,
	})
	finCipher, err := proto.SealFileRaw(finBytes, sessKey, nonceBase, proto.FileSeqFinish, proto.FileAAD("FILE-FINISH", nil, tx))
	if err != nil {
		return "", "", err
	}
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := proto.WriteFrame(conn, proto.MsgFileFinish, finCipher); err != nil {
		return "", "", err
	}

	at, aBody, err := proto.ReadFrame(conn)
	if err != nil {
		return "", "", err
	}
	if at == proto.MsgFileError {
		var werr proto.WireErrorMsg
		if json.Unmarshal(aBody, &werr) == nil && werr.Message != "" {
			return "", "", errors.New(werr.Message)
		}
		return "", "", errors.New("文件校验未通过。")
	}
	if at != proto.MsgFileAck {
		return "", "", errors.New("未能确认对方已完成文件校验保存。")
	}
	ackPlain, err := proto.OpenFileRaw(aBody, sessKey, nonceBase, proto.FileSeqAck, proto.FileAAD("FILE-ACK", nil, tx))
	if err != nil {
		return "", "", errors.New("未能确认对方已完成文件校验保存。")
	}
	var ack proto.FileAckMsg
	if err := json.Unmarshal(ackPlain, &ack); err != nil {
		return "", "", errors.New("未能确认对方已完成文件校验保存。")
	}
	return ack.SavedName, peer.DisplayName, nil
}
