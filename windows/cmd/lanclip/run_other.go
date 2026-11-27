//go:build !windows

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/lintianxu/lan-clip/windows/internal/engine"
)

func runUI(eng *engine.Engine) error {
	eng.Start()
	fmt.Printf("LanClip engine running (device=%s, port=%d)\n", eng.CurrentIdentity().DisplayName, eng.ListeningPort())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
	eng.Shutdown()
	return nil
}
