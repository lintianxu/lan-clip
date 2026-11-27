package proto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/pbkdf2"
)

var Magic = [4]byte{0x4C, 0x43, 0x32, 0x01}

const (
	DefaultPort    uint16 = 47821
	MaxClipBytes          = 1_048_576
	MaxFileBytes   int64  = 4_294_967_296
	FileChunkSize         = 262_144
	MaxFrameBytes         = 1_100_000
	ServiceType           = "_lanclip._tcp"
	PBKDF2Rounds          = 100_000

	FileSeqMeta   uint64 = 0
	FileSeqReady  uint64 = 0xFFFFFFFFFFFFFFFD
	FileSeqFinish uint64 = 0xFFFFFFFFFFFFFFFE
	FileSeqAck    uint64 = 0xFFFFFFFFFFFFFFFF
)

const (
	MsgPairInit      byte = 0x01
	MsgPairChallenge byte = 0x02
	MsgPairProofB    byte = 0x03
	MsgPairProofA    byte = 0x04
	MsgPairError     byte = 0x0F

	MsgClipInit      byte = 0x11
	MsgClipChallenge byte = 0x12
	MsgClipPayload   byte = 0x13
	MsgClipAck       byte = 0x14
	MsgClipError     byte = 0x1F

	MsgFileInit      byte = 0x21
	MsgFileChallenge byte = 0x22
	MsgFileMeta      byte = 0x23
	MsgFileReady     byte = 0x24
	MsgFileChunk     byte = 0x25
	MsgFileFinish    byte = 0x26
	MsgFileAck       byte = 0x27
	MsgFileError     byte = 0x2F
)

type DeviceIdentity struct {
	DeviceID             string `json:"deviceID"`
	DisplayName          string `json:"displayName"`
	Ed25519PrivateKeyB64 string `json:"ed25519PrivateKeyB64"`
}

func (d DeviceIdentity) SigningKey() (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(d.Ed25519PrivateKeyB64)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("本机身份密钥损坏")
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func GenerateIdentity(displayName string) (DeviceIdentity, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	_ = pub
	if err != nil {
		return DeviceIdentity{}, err
	}
	idBytes := make([]byte, 8)
	if _, err := io.ReadFull(rand.Reader, idBytes); err != nil {
		return DeviceIdentity{}, err
	}
	return DeviceIdentity{
		DeviceID:             hex.EncodeToString(idBytes),
		DisplayName:          displayName,
		Ed25519PrivateKeyB64: base64.StdEncoding.EncodeToString(priv.Seed()),
	}, nil
}

type PairedPeer struct {
	DeviceID            string    `json:"deviceID"`
	DisplayName         string    `json:"displayName"`
	Ed25519PublicKeyB64 string    `json:"ed25519PublicKeyB64"`
	LastHost            string    `json:"lastHost"`
	LastPort            uint16    `json:"lastPort"`
	PairedAt            time.Time `json:"pairedAt"`
}

func (p PairedPeer) PublicKey() (ed25519.PublicKey, error) {
	raw, err := base64.StdEncoding.DecodeString(p.Ed25519PublicKeyB64)
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, errors.New("对方身份公钥损坏")
	}
	return ed25519.PublicKey(raw), nil
}

type PersistedState struct {
	Identity        DeviceIdentity `json:"identity"`
	Peers           []PairedPeer   `json:"peers"`
	ActivePeerID    string         `json:"activePeerID,omitempty"`
	ReceiverEnabled bool           `json:"receiverEnabled"`
}

// Wire messages

type PairInitMsg struct {
	BDeviceID    string `json:"bDeviceID"`
	BDisplayName string `json:"bDisplayName"`
	BSignPubB64  string `json:"bSignPubB64"`
	BEphPubB64   string `json:"bEphPubB64"`
	NonceBB64    string `json:"nonceBB64"`
	BListenPort  uint16 `json:"bListenPort"`
}

type PairChallengeMsg struct {
	ADeviceID    string `json:"aDeviceID"`
	ADisplayName string `json:"aDisplayName"`
	ASignPubB64  string `json:"aSignPubB64"`
	AEphPubB64   string `json:"aEphPubB64"`
	NonceAB64    string `json:"nonceAB64"`
	SaltB64      string `json:"saltB64"`
	AListenPort  uint16 `json:"aListenPort"`
}

type PairProofMsg struct {
	ProofB64 string `json:"proofB64"`
}

type WireErrorMsg struct {
	Message string `json:"message"`
}

type ClipInitMsg struct {
	SenderDeviceID string `json:"senderDeviceID"`
	EphPubAB64     string `json:"ephPubAB64"`
	NonceAB64      string `json:"nonceAB64"`
	SigAB64        string `json:"sigAB64"`
}

type ClipChallengeMsg struct {
	EphPubBB64 string `json:"ephPubBB64"`
	NonceBB64  string `json:"nonceBB64"`
	SigBB64    string `json:"sigBB64"`
}

type ClipSealedMsg struct {
	CombinedB64 string `json:"combinedB64"`
}

type FileMetaMsg struct {
	FileName  string `json:"fileName"`
	FileSize  int64  `json:"fileSize"`
	ChunkSize int    `json:"chunkSize"`
}

type FileFinishMsg struct {
	SHA256Hex   string `json:"sha256Hex"`
	TotalChunks uint64 `json:"totalChunks"`
}

type FileAckMsg struct {
	SavedName string `json:"savedName"`
}

// Random & Key Derivation

func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, b)
	return b, err
}

func RandomSixDigitCode() (string, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%06d", n.Int64()), nil
}

func PBKDF2SHA256(code string, salt []byte) []byte {
	return pbkdf2.Key([]byte(code), salt, PBKDF2Rounds, 32, sha256.New)
}

func ComputePairTranscript(
	aDeviceID, bDeviceID string,
	aSignPub, bSignPub, aEphPub, bEphPub, nonceA, nonceB, salt []byte,
) []byte {
	h := sha256.New()
	h.Write([]byte("LANCLIP-PAIR-v2"))
	h.Write([]byte(aDeviceID))
	h.Write([]byte("|"))
	h.Write([]byte(bDeviceID))
	h.Write(aSignPub)
	h.Write(bSignPub)
	h.Write(aEphPub)
	h.Write(bEphPub)
	h.Write(nonceA)
	h.Write(nonceB)
	h.Write(salt)
	return h.Sum(nil)
}

func DerivePairMacKey(sharedSecret, pwKey, salt []byte) ([]byte, error) {
	ikm := make([]byte, 0, len(sharedSecret)+len(pwKey))
	ikm = append(ikm, sharedSecret...)
	ikm = append(ikm, pwKey...)
	r := hkdf.New(sha256.New, ikm, salt, []byte("lanclip-pair-mac-v2"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func ComputePairProof(label string, transcript, macKey []byte) []byte {
	m := hmac.New(sha256.New, macKey)
	m.Write([]byte(label))
	m.Write(transcript)
	return m.Sum(nil)
}

func VerifyPairProof(proof []byte, label string, transcript, macKey []byte) bool {
	expected := ComputePairProof(label, transcript, macKey)
	return hmac.Equal(proof, expected)
}

func X25519Generate() (*ecdh.PrivateKey, error) {
	return ecdh.X25519().GenerateKey(rand.Reader)
}

func X25519Shared(privBytes, pubBytes []byte) ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, err
	}
	pub, err := ecdh.X25519().NewPublicKey(pubBytes)
	if err != nil {
		return nil, err
	}
	return priv.ECDH(pub)
}

// Clipboard Crypto

func ClipInitSignData(senderID, receiverID string, ephPubA, nonceA []byte) []byte {
	out := make([]byte, 0, 64+len(ephPubA)+len(nonceA))
	out = append(out, []byte("LANCLIP-CLIP-INIT-v2")...)
	out = append(out, []byte(senderID)...)
	out = append(out, '|')
	out = append(out, []byte(receiverID)...)
	out = append(out, ephPubA...)
	out = append(out, nonceA...)
	return out
}

func ClipChallengeSignData(receiverID, senderID string, ephPubA, nonceA, ephPubB, nonceB []byte) []byte {
	out := make([]byte, 0, 64+len(ephPubA)+len(nonceA)+len(ephPubB)+len(nonceB))
	out = append(out, []byte("LANCLIP-CLIP-CHAL-v2")...)
	out = append(out, []byte(receiverID)...)
	out = append(out, '|')
	out = append(out, []byte(senderID)...)
	out = append(out, ephPubA...)
	out = append(out, nonceA...)
	out = append(out, ephPubB...)
	out = append(out, nonceB...)
	return out
}

func ClipTranscriptHash(senderID, receiverID string, ephPubA, nonceA, ephPubB, nonceB []byte) []byte {
	h := sha256.New()
	h.Write([]byte("LANCLIP-CLIP-TX-v2"))
	h.Write([]byte(senderID))
	h.Write([]byte("|"))
	h.Write([]byte(receiverID))
	h.Write(ephPubA)
	h.Write(nonceA)
	h.Write(ephPubB)
	h.Write(nonceB)
	return h.Sum(nil)
}

func DeriveClipSessionKey(sharedSecret, transcriptHash []byte) ([]byte, error) {
	r := hkdf.New(sha256.New, sharedSecret, transcriptHash, []byte("lanclip-aes-gcm-v2"))
	out := make([]byte, 32)
	if _, err := io.ReadFull(r, out); err != nil {
		return nil, err
	}
	return out, nil
}

func SealClipData(plain []byte, aadLabel string, transcriptHash, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, err := RandomBytes(12)
	if err != nil {
		return nil, err
	}
	aad := append([]byte(aadLabel), transcriptHash...)
	ctAndTag := gcm.Seal(nil, nonce, plain, aad)
	out := make([]byte, 0, 12+len(ctAndTag))
	out = append(out, nonce...)
	out = append(out, ctAndTag...)
	return out, nil
}

func OpenClipData(combined []byte, aadLabel string, transcriptHash, key []byte) ([]byte, error) {
	if len(combined) < 12+16 {
		return nil, errors.New("密文格式无效")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	aad := append([]byte(aadLabel), transcriptHash...)
	return gcm.Open(nil, combined[:12], combined[12:], aad)
}

// File Crypto (v3)

func FileInitSignData(senderID, receiverID string, ephPubA, nonceA []byte) []byte {
	out := make([]byte, 0, 64+len(ephPubA)+len(nonceA))
	out = append(out, []byte("LANCLIP-FILE-INIT-v3")...)
	out = append(out, []byte(senderID)...)
	out = append(out, '|')
	out = append(out, []byte(receiverID)...)
	out = append(out, ephPubA...)
	out = append(out, nonceA...)
	return out
}

func FileChallengeSignData(receiverID, senderID string, ephPubA, nonceA, ephPubB, nonceB []byte) []byte {
	out := make([]byte, 0, 64+len(ephPubA)+len(nonceA)+len(ephPubB)+len(nonceB))
	out = append(out, []byte("LANCLIP-FILE-CHAL-v3")...)
	out = append(out, []byte(receiverID)...)
	out = append(out, '|')
	out = append(out, []byte(senderID)...)
	out = append(out, ephPubA...)
	out = append(out, nonceA...)
	out = append(out, ephPubB...)
	out = append(out, nonceB...)
	return out
}

func FileTranscriptHash(senderID, receiverID string, ephPubA, nonceA, ephPubB, nonceB []byte) []byte {
	h := sha256.New()
	h.Write([]byte("LANCLIP-FILE-TX-v3"))
	h.Write([]byte(senderID))
	h.Write([]byte("|"))
	h.Write([]byte(receiverID))
	h.Write(ephPubA)
	h.Write(nonceA)
	h.Write(ephPubB)
	h.Write(nonceB)
	return h.Sum(nil)
}

func DeriveFileSessionKeys(sharedSecret, transcriptHash []byte) (key []byte, nonceBase []byte, err error) {
	r1 := hkdf.New(sha256.New, sharedSecret, transcriptHash, []byte("lanclip-file-gcm-v3"))
	key = make([]byte, 32)
	if _, err = io.ReadFull(r1, key); err != nil {
		return nil, nil, err
	}
	r2 := hkdf.New(sha256.New, sharedSecret, transcriptHash, []byte("lanclip-file-nonce-v3"))
	nonceBase = make([]byte, 12)
	if _, err = io.ReadFull(r2, nonceBase); err != nil {
		return nil, nil, err
	}
	return key, nonceBase, nil
}

func FileDeterministicNonce(nonceBase []byte, seq uint64) ([]byte, error) {
	if len(nonceBase) != 12 {
		return nil, errors.New("无效的 nonce 基准长度")
	}
	out := make([]byte, 12)
	copy(out[:4], nonceBase[:4])
	tail := binary.BigEndian.Uint64(nonceBase[4:12]) ^ seq
	binary.BigEndian.PutUint64(out[4:12], tail)
	return out, nil
}

func FileAAD(label string, seqPrefix *uint64, transcriptHash []byte) []byte {
	out := make([]byte, 0, len(label)+8+len(transcriptHash))
	out = append(out, []byte(label)...)
	if seqPrefix != nil {
		var be [8]byte
		binary.BigEndian.PutUint64(be[:], *seqPrefix)
		out = append(out, be[:]...)
	}
	out = append(out, transcriptHash...)
	return out
}

func SealFileRaw(plain, key, nonceBase []byte, seq uint64, aad []byte) ([]byte, error) {
	nonce, err := FileDeterministicNonce(nonceBase, seq)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Seal(nil, nonce, plain, aad), nil
}

func OpenFileRaw(ciphertextAndTag, key, nonceBase []byte, seq uint64, aad []byte) ([]byte, error) {
	if len(ciphertextAndTag) < 16 {
		return nil, errors.New("文件密文格式无效")
	}
	nonce, err := FileDeterministicNonce(nonceBase, seq)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return gcm.Open(nil, nonce, ciphertextAndTag, aad)
}

func ConstantTimeEqualHex(a, b string) bool {
	la := []byte(strings.ToLower(a))
	lb := []byte(strings.ToLower(b))
	if len(la) == 0 || len(la) != len(lb) {
		return false
	}
	return subtle.ConstantTimeCompare(la, lb) == 1
}

// Framing

func WriteFrame(w io.Writer, msgType byte, payload []byte) error {
	if len(payload) > MaxFrameBytes {
		return errors.New("数据包超出安全大小上限")
	}
	var hdr [9]byte
	copy(hdr[:4], Magic[:])
	hdr[4] = msgType
	binary.BigEndian.PutUint32(hdr[5:9], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

func WriteJSONFrame(w io.Writer, msgType byte, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return WriteFrame(w, msgType, data)
}

func ReadFrame(r io.Reader) (byte, []byte, error) {
	var hdr [9]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return 0, nil, err
	}
	if hdr[0] != Magic[0] || hdr[1] != Magic[1] || hdr[2] != Magic[2] || hdr[3] != Magic[3] {
		return 0, nil, errors.New("收到无效的数据包头")
	}
	msgType := hdr[4]
	length := binary.BigEndian.Uint32(hdr[5:9])
	if length > MaxFrameBytes {
		return 0, nil, errors.New("数据包超出安全大小上限")
	}
	body := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
	}
	return msgType, body, nil
}

// Filename sanitization & deduplication

var windowsReservedStems = map[string]bool{
	"CON": true, "PRN": true, "AUX": true, "NUL": true,
	"COM1": true, "COM2": true, "COM3": true, "COM4": true, "COM5": true,
	"COM6": true, "COM7": true, "COM8": true, "COM9": true,
	"LPT1": true, "LPT2": true, "LPT3": true, "LPT4": true, "LPT5": true,
	"LPT6": true, "LPT7": true, "LPT8": true, "LPT9": true,
}

func SanitizeReceivedFileName(raw string) string {
	parts := strings.FieldsFunc(raw, func(r rune) bool {
		return r == '/' || r == '\\'
	})
	base := ""
	if len(parts) > 0 {
		base = parts[len(parts)-1]
	}

	var clean strings.Builder
	for _, r := range base {
		if r < 0x20 || r == 0x7f {
			continue
		}
		switch r {
		case '<', '>', ':', '"', '/', '\\', '|', '?', '*':
			continue
		default:
			clean.WriteRune(r)
		}
	}
	base = strings.TrimLeft(clean.String(), ". ")
	base = strings.TrimRight(base, ". ")
	if base == "" || base == "." || base == ".." {
		return "received_file"
	}

	stem := base
	if dot := strings.IndexByte(base, '.'); dot >= 0 {
		stem = base[:dot]
	}
	if windowsReservedStems[strings.ToUpper(stem)] {
		return "received_file"
	}

	if len(base) > 180 {
		var trunc strings.Builder
		bytes := 0
		for _, r := range base {
			rl := utf8.RuneLen(r)
			if rl < 0 || bytes+rl > 180 {
				break
			}
			trunc.WriteRune(r)
			bytes += rl
		}
		base = strings.TrimRight(trunc.String(), ". ")
		if base == "" {
			return "received_file"
		}
	}
	return base
}

func UniqueDestinationPath(dir, sanitizedName string) string {
	first := filepath.Join(dir, sanitizedName)
	if _, err := os.Stat(first); errors.Is(err, os.ErrNotExist) {
		return first
	}
	ext := filepath.Ext(sanitizedName)
	stem := strings.TrimSuffix(sanitizedName, ext)
	for i := 1; ; i++ {
		var name string
		if ext == "" {
			name = fmt.Sprintf("%s (%d)", stem, i)
		} else {
			name = fmt.Sprintf("%s (%d)%s", stem, i, ext)
		}
		cand := filepath.Join(dir, name)
		if _, err := os.Stat(cand); errors.Is(err, os.ErrNotExist) {
			return cand
		}
	}
}

// LAN IP Allowlist

func IsAllowedIPv4Bytes(a, b, c, d byte) bool {
	if a == 198 && (b == 18 || b == 19) {
		return false
	}
	if a == 10 {
		return true
	}
	if a == 172 && b >= 16 && b <= 31 {
		return true
	}
	if a == 192 && b == 168 {
		return true
	}
	if a == 127 {
		return true
	}
	if a == 169 && b == 254 {
		return true
	}
	return false
}

func IsAllowedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if ip4 := ip.To4(); ip4 != nil {
		return IsAllowedIPv4Bytes(ip4[0], ip4[1], ip4[2], ip4[3])
	}
	ip16 := ip.To16()
	if len(ip16) != 16 {
		return false
	}
	if ip.IsLoopback() {
		return true
	}
	if ip16[0] == 0xfe && (ip16[1]&0xc0) == 0x80 {
		return true
	}
	if (ip16[0] & 0xfe) == 0xfc {
		return true
	}
	return false
}

func DetectLocalLANIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, ifc := range ifaces {
		if (ifc.Flags&net.FlagUp) == 0 || (ifc.Flags&net.FlagLoopback) != 0 {
			continue
		}
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip4 := ipNet.IP.To4()
			if ip4 == nil {
				continue
			}
			if IsAllowedIPv4Bytes(ip4[0], ip4[1], ip4[2], ip4[3]) && ip4[0] != 127 && !(ip4[0] == 169 && ip4[1] == 254) {
				return ip4.String()
			}
		}
	}
	return ""
}

// State Persistence

func DefaultStatePath() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".lan-clip", "state.json")
}

func DefaultDownloadsDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "Downloads", "LanClip")
}

func LoadOrCreateState(path, defaultDisplayName string) (PersistedState, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return PersistedState{}, err
	}
	_ = os.Chmod(dir, 0o700)

	if data, err := os.ReadFile(path); err == nil {
		var st PersistedState
		if err := json.Unmarshal(data, &st); err != nil {
			return PersistedState{}, err
		}
		if _, err := st.Identity.SigningKey(); err != nil {
			return PersistedState{}, err
		}
		return st, nil
	}

	id, err := GenerateIdentity(defaultDisplayName)
	if err != nil {
		return PersistedState{}, err
	}
	st := PersistedState{
		Identity:        id,
		Peers:           []PairedPeer{},
		ReceiverEnabled: true,
	}
	if err := SaveState(st, path); err != nil {
		return PersistedState{}, err
	}
	return st, nil
}

func SaveState(st PersistedState, path string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	_ = os.Chmod(dir, 0o700)
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".state.tmp.*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_ = tmp.Chmod(0o600)
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}
