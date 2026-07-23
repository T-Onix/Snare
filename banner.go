package main

import (
	"fmt"
	"strings"
)

const bannerASCII = `
   ██████╗███╗   ██╗ █████╗ ██████╗ ███████╗
  ██╔════╝████╗  ██║██╔══██╗██╔══██╗██╔════╝
  ╚█████╗ ██╔██╗ ██║███████║██████╔╝█████╗  
   ╚═══██╗██║╚██╗██║██╔══██║██╔══██╗██╔══╝  
  ██████╔╝██║ ╚████║██║  ██║██║  ██║███████╗
  ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝`

func printBanner() {
	lines := strings.Split(bannerASCII, "\n")
	colors := []string{
		ColorGreen,
		ColorBlue,
	}

	fmt.Println()
	for i, line := range lines {
		if strings.TrimSpace(line) == "" {
			continue
		}
		color := colors[i%len(colors)]
		fmt.Printf("%s%s%s\n", color, line, ColorReset)
	}

	fmt.Printf("%s  %sFast Technology Fingerprinting & CVE Discovery Engine%s\n", ColorSubtext, ColorBold, ColorReset)
	fmt.Printf("%s  %sVersion: %sv1.2.0 %s│%s Created by %sT-Onix%s\n\n", ColorSubtext, ColorBlue, ColorGreen, ColorBlue, ColorSubtext, ColorMauve+ColorBold, ColorReset)
}
