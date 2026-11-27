//go:build windows

package main

import (
	"github.com/lintianxu/lan-clip/windows/internal/engine"
	"github.com/lintianxu/lan-clip/windows/internal/winui"
)

func runUI(eng *engine.Engine) error {
	return winui.Run(eng)
}
