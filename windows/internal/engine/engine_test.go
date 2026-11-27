package engine

import (
	"bytes"
	"crypto/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func pickFreePort(t *testing.T) uint16 {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	_ = ln.Close()
	return port
}

func TestGoEngineEndToEnd(t *testing.T) {
	tmp := t.TempDir()
	pA := pickFreePort(t)
	pB := pickFreePort(t)
	engA, err := NewEngine(filepath.Join(tmp, "a", "state.json"), filepath.Join(tmp, "a", "dl"), "Win-A", pA, false)
	if err != nil {
		t.Fatal(err)
	}
	defer engA.Shutdown()

	engB, err := NewEngine(filepath.Join(tmp, "b", "state.json"), filepath.Join(tmp, "b", "dl"), "Mac-B", pB, false)
	if err != nil {
		t.Fatal(err)
	}
	defer engB.Shutdown()

	code1, _, err := engA.StartPairingCodeSession()
	if err != nil {
		t.Fatal(err)
	}
	portA := engA.ListeningPort()
	if portA == 0 {
		t.Fatal("engA failed to listen")
	}

	wrong := "000000"
	if code1 == wrong {
		wrong = "999999"
	}
	for i := 0; i < 5; i++ {
		if _, err := engB.PairWithHost("127.0.0.1", portA, wrong); err == nil {
			t.Fatalf("wrong code succeeded on attempt %d", i)
		}
	}
	if _, err := engB.PairWithHost("127.0.0.1", portA, code1); err == nil {
		t.Fatal("locked code still worked")
	}

	code2, _, err := engA.StartPairingCodeSession()
	if err != nil {
		t.Fatal(err)
	}
	portA2 := engA.ListeningPort()
	if portA2 == 0 {
		t.Fatal("engA failed to re-listen")
	}
	engB.Start()
	peerOnB, err := engB.PairWithHost("127.0.0.1", portA2, code2)
	if err != nil {
		t.Fatalf("valid pair failed: %v", err)
	}
	if peerOnB.DeviceID != engA.CurrentIdentity().DeviceID {
		t.Fatal("wrong deviceID saved on B")
	}
	if len(engA.PairedPeers()) != 1 || engA.PairedPeers()[0].DeviceID != engB.CurrentIdentity().DeviceID {
		t.Fatal("wrong deviceID saved on A")
	}

	// Clipboard A -> B and B -> A
	gotBCh := make(chan string, 1)
	engB.OnTextReceived = func(text, _ string) { gotBCh <- text }
	gotACh := make(chan string, 1)
	engA.OnTextReceived = func(text, _ string) { gotACh <- text }

	if _, _, err := engA.SendText("你好 Windows 😀", ""); err != nil {
		t.Fatalf("A->B text failed: %v", err)
	}
	if got := <-gotBCh; got != "你好 Windows 😀" {
		t.Fatalf("got %q", got)
	}

	if _, _, err := engB.SendText("回传中文 🚀", ""); err != nil {
		t.Fatalf("B->A text failed: %v", err)
	}
	if got := <-gotACh; got != "回传中文 🚀" {
		t.Fatalf("got %q", got)
	}

	// Multi-chunk file transfer + dedup
	payload := make([]byte, 650_000)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	srcFile := filepath.Join(tmp, "录像.mp4")
	if err := os.WriteFile(srcFile, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	recvFileCh := make(chan string, 2)
	engB.OnFileReceived = func(destPath, _, _ string) { recvFileCh <- destPath }

	saved1, _, err := engA.SendFile(srcFile, "")
	if err != nil || saved1 != "录像.mp4" {
		t.Fatalf("sendFile 1 failed: %v (%s)", err, saved1)
	}
	dest1 := <-recvFileCh
	gotBytes1, err := os.ReadFile(dest1)
	if err != nil || !bytes.Equal(gotBytes1, payload) {
		t.Fatal("received file 1 content mismatch")
	}

	saved2, _, err := engA.SendFile(srcFile, "")
	if err != nil || saved2 != "录像 (1).mp4" {
		t.Fatalf("sendFile dedup failed: %v (%s)", err, saved2)
	}
	<-recvFileCh

	// Receiver toggle off/on
	engB.SetReceiverEnabled(false)
	time.Sleep(50 * time.Millisecond)
	if _, _, err := engA.SendText("should fail", ""); err == nil {
		t.Fatal("send succeeded while receiver disabled")
	}
	engB.SetReceiverEnabled(true)
	if _, _, err := engA.SendText("back online", ""); err != nil {
		t.Fatalf("send failed after re-enable: %v", err)
	}
}
