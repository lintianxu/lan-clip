package proto

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestVectorsMatchSwift(t *testing.T) {
	vecPath := filepath.Join("..", "..", "..", "protocol", "test_vectors.json")
	raw, err := os.ReadFile(vecPath)
	if err != nil {
		t.Fatalf("read test_vectors.json: %v", err)
	}
	var root struct {
		Ed25519 struct {
			PrivHex string `json:"privHex"`
			PubHex  string `json:"pubHex"`
			MsgHex  string `json:"msgHex"`
			SigHex  string `json:"sigHex"`
		} `json:"ed25519"`
		Pairing struct {
			ADeviceID       string `json:"aDeviceID"`
			BDeviceID       string `json:"bDeviceID"`
			ASignPubHex     string `json:"aSignPubHex"`
			BSignPubHex     string `json:"bSignPubHex"`
			AEphPrivHex     string `json:"aEphPrivHex"`
			AEphPubHex      string `json:"aEphPubHex"`
			BEphPrivHex     string `json:"bEphPrivHex"`
			BEphPubHex      string `json:"bEphPubHex"`
			NonceAHex       string `json:"nonceAHex"`
			NonceBHex       string `json:"nonceBHex"`
			SaltHex         string `json:"saltHex"`
			Code            string `json:"code"`
			SharedSecretHex string `json:"sharedSecretHex"`
			PWKeyHex        string `json:"pwKeyHex"`
			TranscriptHex   string `json:"transcriptHex"`
			MacKeyHex       string `json:"macKeyHex"`
			ProofBHex       string `json:"proofBHex"`
			ProofAHex       string `json:"proofAHex"`
		} `json:"pairing"`
		Clipboard struct {
			SenderID        string `json:"senderID"`
			ReceiverID      string `json:"receiverID"`
			EphPrivAHex     string `json:"ephPrivAHex"`
			EphPubAHex      string `json:"ephPubAHex"`
			EphPubBHex      string `json:"ephPubBHex"`
			NonceAHex       string `json:"nonceAHex"`
			NonceBHex       string `json:"nonceBHex"`
			InitSignDataHex string `json:"initSignDataHex"`
			ChalSignDataHex string `json:"chalSignDataHex"`
			TxHashHex       string `json:"txHashHex"`
			SessionKeyHex   string `json:"sessionKeyHex"`
			PlainHex        string `json:"plainHex"`
			CombinedB64     string `json:"combinedB64"`
			AckCombinedB64  string `json:"ackCombinedB64"`
		} `json:"clipboard"`
		File struct {
			SenderID        string `json:"senderID"`
			ReceiverID      string `json:"receiverID"`
			EphPrivAHex     string `json:"ephPrivAHex"`
			EphPubAHex      string `json:"ephPubAHex"`
			EphPubBHex      string `json:"ephPubBHex"`
			NonceAHex       string `json:"nonceAHex"`
			NonceBHex       string `json:"nonceBHex"`
			InitSignDataHex string `json:"initSignDataHex"`
			ChalSignDataHex string `json:"chalSignDataHex"`
			TxHashHex       string `json:"txHashHex"`
			SessionKeyHex   string `json:"sessionKeyHex"`
			NonceBaseHex    string `json:"nonceBaseHex"`
			MetaSeq         string `json:"metaSeq"`
			MetaPlainHex    string `json:"metaPlainHex"`
			MetaCipherHex   string `json:"metaCipherHex"`
			ReadySeq        string `json:"readySeq"`
			ReadyPlainHex   string `json:"readyPlainHex"`
			ReadyCipherHex  string `json:"readyCipherHex"`
			Chunk1Seq       string `json:"chunk1Seq"`
			Chunk1PlainHex  string `json:"chunk1PlainHex"`
			Chunk1CipherHex string `json:"chunk1CipherHex"`
			Chunk2Seq       string `json:"chunk2Seq"`
			Chunk2PlainHex  string `json:"chunk2PlainHex"`
			Chunk2CipherHex string `json:"chunk2CipherHex"`
			FinishSeq       string `json:"finishSeq"`
			FinishPlainHex  string `json:"finishPlainHex"`
			FinishCipherHex string `json:"finishCipherHex"`
			AckSeq          string `json:"ackSeq"`
			AckPlainHex     string `json:"ackPlainHex"`
			AckCipherHex    string `json:"ackCipherHex"`
		} `json:"file"`
	}
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("unmarshal vectors: %v", err)
	}

	// 1. Ed25519
	priv := ed25519.NewKeyFromSeed(mustHex(t, root.Ed25519.PrivHex))
	pub := priv.Public().(ed25519.PublicKey)
	if hex.EncodeToString(pub) != root.Ed25519.PubHex {
		t.Fatalf("ed25519 pub mismatch")
	}
	msg := mustHex(t, root.Ed25519.MsgHex)
	swiftSig := mustHex(t, root.Ed25519.SigHex)
	if !ed25519.Verify(pub, msg, swiftSig) {
		t.Fatalf("ed25519 swift signature failed verification")
	}
	goSig := ed25519.Sign(priv, msg)
	if !ed25519.Verify(pub, msg, goSig) {
		t.Fatalf("ed25519 go signature failed verification")
	}
	tampered := append([]byte(nil), swiftSig...)
	tampered[0] ^= 0xff
	if ed25519.Verify(pub, msg, tampered) {
		t.Fatalf("tampered signature unexpectedly passed verification")
	}

	// 2. Pairing
	shared, err := X25519Shared(mustHex(t, root.Pairing.AEphPrivHex), mustHex(t, root.Pairing.BEphPubHex))
	if err != nil {
		t.Fatalf("x25519 failed: %v", err)
	}
	if hex.EncodeToString(shared) != root.Pairing.SharedSecretHex {
		t.Fatalf("x25519 shared mismatch")
	}
	pwKey := PBKDF2SHA256(root.Pairing.Code, mustHex(t, root.Pairing.SaltHex))
	if hex.EncodeToString(pwKey) != root.Pairing.PWKeyHex {
		t.Fatalf("pbkdf2 mismatch")
	}
	tx := ComputePairTranscript(
		root.Pairing.ADeviceID, root.Pairing.BDeviceID,
		mustHex(t, root.Pairing.ASignPubHex), mustHex(t, root.Pairing.BSignPubHex),
		mustHex(t, root.Pairing.AEphPubHex), mustHex(t, root.Pairing.BEphPubHex),
		mustHex(t, root.Pairing.NonceAHex), mustHex(t, root.Pairing.NonceBHex),
		mustHex(t, root.Pairing.SaltHex),
	)
	if hex.EncodeToString(tx) != root.Pairing.TranscriptHex {
		t.Fatalf("pair transcript mismatch")
	}
	macKey, err := DerivePairMacKey(shared, pwKey, mustHex(t, root.Pairing.SaltHex))
	if err != nil || hex.EncodeToString(macKey) != root.Pairing.MacKeyHex {
		t.Fatalf("macKey mismatch: %v", err)
	}
	if !VerifyPairProof(mustHex(t, root.Pairing.ProofBHex), "PROOF-B", tx, macKey) {
		t.Fatalf("proofB mismatch")
	}
	if !VerifyPairProof(mustHex(t, root.Pairing.ProofAHex), "PROOF-A", tx, macKey) {
		t.Fatalf("proofA mismatch")
	}

	// 3. Clipboard
	clipInit := ClipInitSignData(root.Clipboard.SenderID, root.Clipboard.ReceiverID, mustHex(t, root.Clipboard.EphPubAHex), mustHex(t, root.Clipboard.NonceAHex))
	if hex.EncodeToString(clipInit) != root.Clipboard.InitSignDataHex {
		t.Fatalf("clipInitSignData mismatch")
	}
	clipChal := ClipChallengeSignData(root.Clipboard.ReceiverID, root.Clipboard.SenderID, mustHex(t, root.Clipboard.EphPubAHex), mustHex(t, root.Clipboard.NonceAHex), mustHex(t, root.Clipboard.EphPubBHex), mustHex(t, root.Clipboard.NonceBHex))
	if hex.EncodeToString(clipChal) != root.Clipboard.ChalSignDataHex {
		t.Fatalf("clipChalSignData mismatch")
	}
	clipTx := ClipTranscriptHash(root.Clipboard.SenderID, root.Clipboard.ReceiverID, mustHex(t, root.Clipboard.EphPubAHex), mustHex(t, root.Clipboard.NonceAHex), mustHex(t, root.Clipboard.EphPubBHex), mustHex(t, root.Clipboard.NonceBHex))
	if hex.EncodeToString(clipTx) != root.Clipboard.TxHashHex {
		t.Fatalf("clipTx mismatch")
	}
	clipKey, err := DeriveClipSessionKey(shared, clipTx)
	if err != nil || hex.EncodeToString(clipKey) != root.Clipboard.SessionKeyHex {
		t.Fatalf("clipKey mismatch")
	}
	combined, err := base64.StdEncoding.DecodeString(root.Clipboard.CombinedB64)
	if err != nil {
		t.Fatalf("b64: %v", err)
	}
	clipOpened, err := OpenClipData(combined, "PAYLOAD", clipTx, clipKey)
	if err != nil || hex.EncodeToString(clipOpened) != root.Clipboard.PlainHex {
		t.Fatalf("clip open mismatch: %v", err)
	}
	ackBytes, _ := base64.StdEncoding.DecodeString(root.Clipboard.AckCombinedB64)
	ackOpened, err := OpenClipData(ackBytes, "ACK", clipTx, clipKey)
	if err != nil || string(ackOpened) != "OK" {
		t.Fatalf("clip ack mismatch: %v", err)
	}

	// 4. Streaming File Vectors (exact byte-for-byte deterministic ciphertext!)
	if hex.EncodeToString(FileInitSignData(root.File.SenderID, root.File.ReceiverID, mustHex(t, root.File.EphPubAHex), mustHex(t, root.File.NonceAHex))) != root.File.InitSignDataHex {
		t.Fatalf("fileInitSignData mismatch")
	}
	if hex.EncodeToString(FileChallengeSignData(root.File.ReceiverID, root.File.SenderID, mustHex(t, root.File.EphPubAHex), mustHex(t, root.File.NonceAHex), mustHex(t, root.File.EphPubBHex), mustHex(t, root.File.NonceBHex))) != root.File.ChalSignDataHex {
		t.Fatalf("fileChalSignData mismatch")
	}
	fileTx := FileTranscriptHash(root.File.SenderID, root.File.ReceiverID, mustHex(t, root.File.EphPubAHex), mustHex(t, root.File.NonceAHex), mustHex(t, root.File.EphPubBHex), mustHex(t, root.File.NonceBHex))
	if hex.EncodeToString(fileTx) != root.File.TxHashHex {
		t.Fatalf("fileTx mismatch")
	}
	fileKey, nonceBase, err := DeriveFileSessionKeys(shared, fileTx)
	if err != nil || hex.EncodeToString(fileKey) != root.File.SessionKeyHex || hex.EncodeToString(nonceBase) != root.File.NonceBaseHex {
		t.Fatalf("file session keys mismatch")
	}

	checkFileStage := func(seqStr, label string, seqPref *uint64, plainHex, cipherHex string) {
		t.Helper()
		seq, err := strconv.ParseUint(seqStr, 10, 64)
		if err != nil {
			t.Fatalf("parse seq %s: %v", seqStr, err)
		}
		aad := FileAAD(label, seqPref, fileTx)
		plain := mustHex(t, plainHex)
		sealed, err := SealFileRaw(plain, fileKey, nonceBase, seq, aad)
		if err != nil {
			t.Fatalf("seal %s: %v", label, err)
		}
		if hex.EncodeToString(sealed) != cipherHex {
			t.Fatalf("%s deterministic ciphertext mismatch", label)
		}
		opened, err := OpenFileRaw(mustHex(t, cipherHex), fileKey, nonceBase, seq, aad)
		if err != nil || !bytes.Equal(opened, plain) {
			t.Fatalf("open %s failed: %v", label, err)
		}
	}

	var s1 uint64 = 1
	var s2 uint64 = 2
	checkFileStage(root.File.MetaSeq, "FILE-META", nil, root.File.MetaPlainHex, root.File.MetaCipherHex)
	checkFileStage(root.File.ReadySeq, "FILE-READY", nil, root.File.ReadyPlainHex, root.File.ReadyCipherHex)
	checkFileStage(root.File.Chunk1Seq, "FILE-CHUNK", &s1, root.File.Chunk1PlainHex, root.File.Chunk1CipherHex)
	checkFileStage(root.File.Chunk2Seq, "FILE-CHUNK", &s2, root.File.Chunk2PlainHex, root.File.Chunk2CipherHex)
	checkFileStage(root.File.FinishSeq, "FILE-FINISH", nil, root.File.FinishPlainHex, root.File.FinishCipherHex)
	checkFileStage(root.File.AckSeq, "FILE-ACK", nil, root.File.AckPlainHex, root.File.AckCipherHex)
}

func TestIPAllowlistAndSanitize(t *testing.T) {
	allowed := []string{"192.168.1.10", "10.0.0.1", "172.16.0.1", "127.0.0.1", "169.254.1.1", "::1", "fe80::1", "fd00::1"}
	for _, s := range allowed {
		if !IsAllowedIP(net.ParseIP(s)) {
			t.Fatalf("expected %s allowed", s)
		}
	}
	blocked := []string{"198.18.0.1", "198.19.255.254", "8.8.8.8", "1.1.1.1", "2001:4860:4860::8888"}
	for _, s := range blocked {
		if IsAllowedIP(net.ParseIP(s)) {
			t.Fatalf("expected %s blocked", s)
		}
	}
	if SanitizeReceivedFileName("../../etc/passwd") != "passwd" {
		t.Fatalf("unix traversal failed")
	}
	if SanitizeReceivedFileName(`..\..\Windows\System32\evil.exe`) != "evil.exe" {
		t.Fatalf("win traversal failed")
	}
	if SanitizeReceivedFileName("CON.txt") != "received_file" || SanitizeReceivedFileName("nul") != "received_file" {
		t.Fatalf("reserved windows name failed")
	}
}
