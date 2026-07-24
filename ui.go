package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

// Catppuccin 24-bit TrueColor ANSI Escape Codes
const (
	ColorReset   = "\x1b[0m"
	ColorBold    = "\x1b[1m"
	ColorMauve   = "\x1b[38;2;203;166;247m" // Magenta / Mauve
	ColorBlue    = "\x1b[38;2;137;180;250m" // Blue
	ColorGreen   = "\x1b[38;2;166;227;161m" // Green
	ColorRed     = "\x1b[38;2;243;139;168m" // Red
	ColorSubtext = "\x1b[38;2;166;173;200m"
)

type TargetResult struct {
	Target       string       `json:"target"`
	Timestamp    string       `json:"timestamp"`
	Technologies []TechResult `json:"technologies"`
}

var (
	stdoutMutex sync.Mutex
	outputFile  *os.File
	ansiRegex   = regexp.MustCompile(`\x1b\[[0-9;]*m`)
	isJSONMode  bool
)

func setJSONMode(enabled bool) {
	isJSONMode = enabled
}

func initOutputFile(path string) error {
	if path == "" {
		return nil
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return err
	}
	outputFile = f
	return nil
}

func closeOutputFile() {
	if outputFile != nil {
		outputFile.Close()
	}
}

func renderTargetCard(targetURL string, results []TechResult) {
	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()

	if isJSONMode {
		renderJSONOutput(targetURL, results)
		return
	}

	const boxWidth = 110
	const innerWidth = boxWidth - 4

	var uiLines []string
	var rawLines []string

	// Raw Target Line for File Export
	rawLines = append(rawLines, fmt.Sprintf("TARGET: %s", targetURL))

	// UI Card Header
	headerLine := fmt.Sprintf("%sTARGET:%s %s%s%s", ColorMauve+ColorBold, ColorReset, ColorBlue, targetURL, ColorReset)
	uiLines = append(uiLines, headerLine)
	uiLines = append(uiLines, "DIVIDER")

	for _, res := range results {
		if res.Tech.Version == "" {
			uiLines = append(uiLines, fmt.Sprintf("%sTech:%s %s%s%s %s(Version unknown)%s",
				ColorSubtext, ColorReset, ColorBlue, res.Tech.Name, ColorReset, ColorSubtext, ColorReset))
			rawLines = append(rawLines, fmt.Sprintf("  - Tech: %s (Version unknown)", res.Tech.Name))
		} else {
			uiLines = append(uiLines, fmt.Sprintf("%sTech:%s %s%s%s %sv%s%s",
				ColorSubtext, ColorReset, ColorBlue+ColorBold, res.Tech.Name, ColorReset, ColorGreen, res.Tech.Version, ColorReset))
			rawLines = append(rawLines, fmt.Sprintf("  - Tech: %s v%s", res.Tech.Name, res.Tech.Version))

			if len(res.CVEs) > 0 {
				for i, cve := range res.CVEs {
					isLast := (i == len(res.CVEs)-1)

					branch := "  ├─ "
					pipeIndent := "  │ "
					if isLast {
						branch = "  └─ "
						pipeIndent = "     "
					}

					vulnTag := fmt.Sprintf("%s[VULNERABLE]%s", ColorRed+ColorBold, ColorReset)
					cveTag := fmt.Sprintf("%s%s%s", ColorGreen+ColorBold, cve.ID, ColorReset)

					prefixVisLen := 5 + 12 + 1 + len(cve.ID) + 4
					maxSummaryWidth := innerWidth - prefixVisLen
					if maxSummaryWidth < 30 {
						maxSummaryWidth = 30
					}

					summaryLines := wrapWords(cve.Summary, maxSummaryWidth)

					firstLine := fmt.Sprintf("%s%s %s -> %s%s%s", branch, vulnTag, cveTag, ColorSubtext, summaryLines[0], ColorReset)
					uiLines = append(uiLines, firstLine)

					if len(summaryLines) > 1 {
						contIndent := pipeIndent + strings.Repeat(" ", prefixVisLen-visibleLength(pipeIndent))
						for _, sl := range summaryLines[1:] {
							uiLines = append(uiLines, fmt.Sprintf("%s%s%s%s", contIndent, ColorSubtext, sl, ColorReset))
						}
					}

					rawLines = append(rawLines, fmt.Sprintf("    * [VULNERABLE] %s -> %s", cve.ID, cve.Summary))
				}
			} else {
				safeTag := fmt.Sprintf("%s[SAFE]%s", ColorGreen+ColorBold, ColorReset)
				uiLines = append(uiLines, fmt.Sprintf("  └─ %s No known public CVEs indexed", safeTag))
				rawLines = append(rawLines, "    * [SAFE] No known public CVEs indexed")
			}
		}
	}

	var box strings.Builder
	border := ColorMauve

	// Top Border
	box.WriteString(border + "╭" + strings.Repeat("─", boxWidth-2) + "╮" + ColorReset + "\n")

	for _, line := range uiLines {
		if line == "DIVIDER" {
			box.WriteString(border + "├" + strings.Repeat("─", boxWidth-2) + "┤" + ColorReset + "\n")
			continue
		}

		visLen := visibleLength(line)
		padding := boxWidth - 4 - visLen
		if padding < 0 {
			padding = 0
		}

		box.WriteString(fmt.Sprintf("%s│%s %s%s %s│%s\n", border, ColorReset, line, strings.Repeat(" ", padding), border, ColorReset))
	}

	// Bottom Border
	box.WriteString(border + "╰" + strings.Repeat("─", boxWidth-2) + "╯" + ColorReset + "\n")

	fmt.Print(box.String())

	if outputFile != nil {
		rawBlock := strings.Join(rawLines, "\n") + "\n\n"
		outputFile.WriteString(rawBlock)
	}
}

func renderJSONOutput(targetURL string, results []TechResult) {
	if results == nil {
		results = []TechResult{}
	}

	record := TargetResult{
		Target:       targetURL,
		Timestamp:    time.Now().UTC().Format(time.RFC3339),
		Technologies: results,
	}

	jsonData, err := json.Marshal(record)
	if err != nil {
		return
	}

	jsonString := string(jsonData)

	// Print JSON string directly to stdout
	fmt.Println(jsonString)

	// Write JSON line to file if output file is specified
	if outputFile != nil {
		outputFile.WriteString(jsonString + "\n")
	}
}

func wrapWords(text string, maxLen int) []string {
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\r", "")
	words := strings.Fields(text)

	if len(words) == 0 {
		return []string{""}
	}

	var lines []string
	currentLine := words[0]

	for _, word := range words[1:] {
		if len(currentLine)+1+len(word) <= maxLen {
			currentLine += " " + word
		} else {
			lines = append(lines, currentLine)
			currentLine = word
		}
	}
	lines = append(lines, currentLine)
	return lines
}

func visibleLength(s string) int {
	clean := ansiRegex.ReplaceAllString(s, "")
	return len([]rune(clean))
}
