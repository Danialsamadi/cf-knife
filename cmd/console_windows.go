//go:build windows
// +build windows

package cmd

import (
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procSetConsoleMode           = kernel32.NewProc("SetConsoleMode")
	procGetConsoleMode           = kernel32.NewProc("GetConsoleMode")
)

const enableVirtualTerminalProcessing = 0x0004

func init() {
	enableANSI(os.Stdout)
	enableANSI(os.Stderr)
}

func enableANSI(f *os.File) {
	handle := f.Fd()
	var mode uint32
	r, _, _ := procGetConsoleMode.Call(handle, uintptr(unsafe.Pointer(&mode)))
	if r == 0 {
		return
	}
	procSetConsoleMode.Call(handle, uintptr(mode|enableVirtualTerminalProcessing))
}
