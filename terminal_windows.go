//go:build windows

package main

// terminalWidth falls back to a conservative width on Windows. The bar drops
// its graphical portion when space is tight, so the count and percent still
// render correctly without a console ioctl here.
func terminalWidth() int {
	return 80
}
