package main

import (
	"fmt"
	"os"

	"github.com/lintianxu/lan-clip/windows/internal/engine"
	"github.com/lintianxu/lan-clip/windows/internal/proto"
)

func main() {
	host, _ := os.Hostname()
	if host == "" {
		host = "Windows-PC"
	}
	eng, err := engine.NewEngine(proto.DefaultStatePath(), proto.DefaultDownloadsDir(), host, proto.DefaultPort, true)
	if err != nil {
		fmt.Fprintf(os.Stderr, "init error: %v\n", err)
		os.Exit(1)
	}
	if err := runUI(eng); err != nil {
		fmt.Fprintf(os.Stderr, "ui error: %v\n", err)
		os.Exit(1)
	}
}
