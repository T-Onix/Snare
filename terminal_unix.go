//go:build !windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

// terminalWidth uses the standard TIOCGWINSZ ioctl on stdout. A failure means
// output is not a terminal or the platform cannot answer, so use a safe
// default rather than depending on an extra module.
func terminalWidth() int {
	fd := os.Stdout.Fd()
	var winsize struct {
		row, col, xpixel, ypixel uint16
	}
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCGWINSZ), uintptr(unsafe.Pointer(&winsize)))
	if errno == 0 && winsize.col > 0 {
		return int(winsize.col)
	}
	return 80
}
