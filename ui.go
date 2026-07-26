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
	ColorReset    = "\x1b[0m"
	ColorBold     = "\x1b[1m"
	ColorMauve    = "\x1b[38;2;203;166;247m" // Header Border
	ColorBlue     = "\x1b[38;2;137;180;250m" // Target Blue / Low Severity
	ColorGreen    = "\x1b[38;2;166;227;161m" // Safe / Success
	ColorYellow   = "\x1b[38;2;249;226;175m" // Medium Severity
	ColorPeach    = "\x1b[38;2;250;179;135m" // High Severity
	ColorRed      = "\x1b[38;2;243;139;168m" // Critical Severity
	ColorSubtext  = "\x1b[38;2;166;173;200m" // Gray / Secondary Info
	ColorFlamingo = "\x1b[38;2;242;205;205m" // PoC Highlight
)

type TargetResult struct {
	Target       string       `json:"target"`
	Timestamp    string       `json:"timestamp"`
	Technologies []TechResult `json:"technologies"`
}

var (
	stdoutMutex sync.Mutex
	outputFile  *os.File
	ansiRegex   = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)
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

func getSeverityBadge(severity string, cvss float64) (uiBadge string, rawBadge string) {
	upperSev := strings.ToUpper(severity)
	if upperSev == "" {
		upperSev = "UNKNOWN"
	}

	scoreStr := ""
	if cvss > 0.0 {
		scoreStr = fmt.Sprintf(" %.1f", cvss)
	}

	rawBadge = fmt.Sprintf("[%s%s]", upperSev, scoreStr)

	switch upperSev {
	case "CRITICAL":
		uiBadge = fmt.Sprintf("%s%s[%s%s]%s", ColorRed, ColorBold, upperSev, scoreStr, ColorReset)
	case "HIGH":
		uiBadge = fmt.Sprintf("%s%s[%s%s]%s", ColorPeach, ColorBold, upperSev, scoreStr, ColorReset)
	case "MEDIUM":
		uiBadge = fmt.Sprintf("%s%s[%s%s]%s", ColorYellow, ColorBold, upperSev, scoreStr, ColorReset)
	case "LOW":
		uiBadge = fmt.Sprintf("%s%s[%s%s]%s", ColorBlue, ColorBold, upperSev, scoreStr, ColorReset)
	default:
		uiBadge = fmt.Sprintf("%s[%s%s]%s", ColorSubtext, upperSev, scoreStr, ColorReset)
	}

	return uiBadge, rawBadge
}

func renderTargetCard(targetURL string, results []TechResult) {
	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()

	if isJSONMode {
		renderJSONOutput(targetURL, results)
		return
	}

	const boxWidth = 115
	const innerWidth = boxWidth - 4

	var uiLines []string
	var rawLines []string

	rawLines = append(rawLines, fmt.Sprintf("TARGET: %s", targetURL))

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

					uiBadge, rawBadge := getSeverityBadge(cve.Severity, cve.CVSS)
					cveTag := fmt.Sprintf("%s%s%s", ColorGreen+ColorBold, cve.ID, ColorReset)

					pocUI := ""
					pocRaw := ""
					if cve.HasPoC {
						pocUI = fmt.Sprintf(" %s%s[🔥 PoC AVAILABLE]%s", ColorFlamingo, ColorBold, ColorReset)
						pocRaw = " [PoC AVAILABLE]"
					}

					prefixVisLen := visibleLength(branch) + visibleLength(uiBadge) + visibleLength(pocUI) + 1 + len(cve.ID) + 4
					maxSummaryWidth := innerWidth - prefixVisLen
					if maxSummaryWidth < 20 {
						maxSummaryWidth = 20
					}

					summaryLines := wrapWords(cve.Summary, maxSummaryWidth)

					firstLine := fmt.Sprintf("%s%s%s %s -> %s%s%s", branch, uiBadge, pocUI, cveTag, ColorSubtext, summaryLines[0], ColorReset)
					uiLines = append(uiLines, firstLine)

					if len(summaryLines) > 1 {
						contIndent := pipeIndent + strings.Repeat(" ", prefixVisLen-visibleLength(pipeIndent))
						for _, sl := range summaryLines[1:] {
							uiLines = append(uiLines, fmt.Sprintf("%s%s%s%s", contIndent, ColorSubtext, sl, ColorReset))
						}
					}

					rawLines = append(rawLines, fmt.Sprintf("    * %s%s %s -> %s", rawBadge, pocRaw, cve.ID, cve.Summary))
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

	fmt.Println(jsonString)

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

// runeWidth calculates the visual display width of a Unicode character in terminal monospace fonts
func runeWidth(r rune) int {
	// Emojis and wide character ranges (occupy 2 terminal cells)
	if (r >= 0x1F300 && r <= 0x1F9FF) || // Misc Symbols, Pictographs, Supplemental
		(r >= 0x2600 && r <= 0x26FF) || // Misc Symbols
		(r >= 0x2700 && r <= 0x27BF) || // Dingbats
		(r >= 0xFE00 && r <= 0xFE0F) || // Variation Selectors
		(r >= 0x1F000 && r <= 0x1F02F) ||
		(r >= 0x1F0A0 && r <= 0x1F0FF) ||
		(r >= 0x20000 && r <= 0x3FFFF) {
		return 2
	}
	return 1
}

// visibleLength calculates exact visual width in terminal cells, ignoring ANSI escape codes
func visibleLength(s string) int {
	clean := ansiRegex.ReplaceAllString(s, "")
	width := 0
	for _, r := range clean {
		width += runeWidth(r)
	}
	return width
}
