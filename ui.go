package main

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"
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
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
	if err != nil {
		return err
	}
	if err := f.Chmod(0600); err != nil {
		_ = f.Close()
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

			if res.CVEStatus == "offline_fallback" || res.CVEStatus == "bundled_fallback" {
				warning := "Bundled version rules used; verify vendor advisories, distro backports, and configuration"
				uiLines = append(uiLines, fmt.Sprintf("  ├─ %s[OFFLINE FALLBACK]%s %s", ColorPeach+ColorBold, ColorReset, warning))
				rawLines = append(rawLines, "    * [OFFLINE FALLBACK] "+warning)
			}
			if res.CVEStatus == "matched_partial" && res.CVEError != "" {
				warning := "Some sources failed; results may be incomplete. " + compactDiagnostic(res.CVEError)
				uiLines = append(uiLines, fmt.Sprintf("  ├─ %s[PARTIAL LOOKUP]%s %s", ColorPeach+ColorBold, ColorReset, warning))
				rawLines = append(rawLines, "    * [PARTIAL LOOKUP] "+warning+" | "+res.CVEError)
			}

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
					for _, reference := range cve.References {
						rawLines = append(rawLines, "      Reference: "+reference)
					}
				}
			} else {
				// Absence of a matching record is not evidence that software is safe.
				status := res.CVEStatus
				label := "[NO MATCHED CVEs]"
				detail := "No version-matched CVEs returned by the current source"
				color := ColorSubtext
				switch status {
				case "lookup_error":
					label = "[LOOKUP UNAVAILABLE]"
					detail = "CIRCL, OSV, and NVD lookups failed; check DNS, proxy, and API reachability"
					if res.CVEError != "" {
						detail = "Source errors: " + compactDiagnostic(res.CVEError)
					}
					color = ColorPeach
				case "partial_lookup":
					label = "[PARTIAL LOOKUP]"
					detail = "Some vulnerability sources failed; a no-match result is incomplete"
					if res.CVEError != "" {
						detail = "Partial source errors: " + compactDiagnostic(res.CVEError)
					}
					color = ColorPeach
				case "unsupported_product":
					label = "[PRODUCT UNMAPPED]"
					detail = "No reliable vendor/product mapping is available for this technology"
					color = ColorPeach
				case "version_unknown":
					label = "[VERSION UNKNOWN]"
					detail = "Version was not identified; version-based CVE matching was skipped"
				}
				uiLines = append(uiLines, fmt.Sprintf("  └─ %s%s%s %s", color+ColorBold, label, ColorReset, detail))
				rawLines = append(rawLines, fmt.Sprintf("    * %s %s", label, detail))
			}
		}
	}

	// A provider error, URL, CVE description, or even a single unbroken token
	// can be longer than the card. Wrap the final composed rows (not only CVE
	// summaries) so every printed line stays inside the border. This is the
	// final guard against regressions when a new provider adds longer messages.
	wrappedLines := make([]string, 0, len(uiLines))
	for _, line := range uiLines {
		if line == "DIVIDER" {
			wrappedLines = append(wrappedLines, line)
			continue
		}
		wrappedLines = append(wrappedLines, wrapANSI(line, innerWidth)...)
	}
	uiLines = wrappedLines

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

func compactDiagnostic(value string) string {
	value = strings.ReplaceAll(value, "\r", " ")
	value = strings.ReplaceAll(value, "\n", " ")
	return strings.Join(strings.Fields(value), " ")
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

type displayToken struct {
	raw        string
	width      int
	whitespace bool
	ansi       bool
}

type displayWord struct {
	tokens []displayToken
	width  int
}

// wrapANSI wraps fully formatted UI lines using terminal-cell width rather
// than byte count. ANSI SGR styles have zero width and are restored after line
// breaks; oversized words/URLs are split too, so nothing can escape the card.
func wrapANSI(text string, maxWidth int) []string {
	if maxWidth < 1 {
		maxWidth = 1
	}
	text = strings.ReplaceAll(text, "\r", " ")
	text = strings.ReplaceAll(text, "\n", " ")
	text = strings.ReplaceAll(text, "\t", " ")
	tokens := tokenizeDisplayText(text)

	words := make([]displayWord, 0, 16)
	current := displayWord{}
	finishWord := func() {
		if len(current.tokens) == 0 {
			return
		}
		words = append(words, current)
		current = displayWord{}
	}
	for _, token := range tokens {
		if token.whitespace {
			finishWord()
			continue
		}
		current.tokens = append(current.tokens, token)
		current.width += token.width
	}
	finishWord()
	if len(words) == 0 {
		return []string{""}
	}

	indentWidth := 4
	if indentWidth > maxWidth/3 {
		indentWidth = maxWidth / 3
	}
	indent := strings.Repeat(" ", indentWidth)
	var lines []string
	line := strings.Builder{}
	lineWidth := 0
	lineHasWord := false
	activeStyle := ""

	applyToken := func(token displayToken) {
		line.WriteString(token.raw)
		if token.ansi {
			activeStyle = updateANSIStyle(activeStyle, token.raw)
		} else {
			lineWidth += token.width
			if token.width > 0 {
				lineHasWord = true
			}
		}
	}
	startContinuation := func() {
		line.Reset()
		line.WriteString(indent)
		line.WriteString(activeStyle)
		lineWidth = indentWidth
		lineHasWord = false
	}
	flushLine := func() {
		if !lineHasWord {
			return
		}
		value := strings.TrimRight(line.String(), " ")
		if activeStyle != "" {
			value += ColorReset
		}
		lines = append(lines, value)
		startContinuation()
	}

	for _, word := range words {
		if word.width <= maxWidth {
			spaceWidth := 0
			if lineHasWord {
				spaceWidth = 1
			}
			if lineWidth+spaceWidth+word.width > maxWidth && lineHasWord {
				flushLine()
			}
			// A wide word may fit a fresh row but not fit after the continuation
			// indent. Remove that indent rather than allowing the border to drift.
			if !lineHasWord && lineWidth > 0 && lineWidth+word.width > maxWidth {
				line.Reset()
				line.WriteString(activeStyle)
				lineWidth = 0
			}
			if lineHasWord {
				line.WriteByte(' ')
				lineWidth++
			}
			for _, token := range word.tokens {
				applyToken(token)
			}
			continue
		}

		// Long unbroken words (most often URLs or provider diagnostics) need
		// character-level splitting. Start them on a fresh line when possible.
		if lineHasWord {
			flushLine()
		} else if lineWidth > 0 {
			line.Reset()
			line.WriteString(activeStyle)
			lineWidth = 0
		}
		for _, token := range word.tokens {
			if !token.ansi && token.width > 0 && lineHasWord && lineWidth+token.width > maxWidth {
				flushLine()
			}
			applyToken(token)
		}
	}

	if lineHasWord {
		value := strings.TrimRight(line.String(), " ")
		if activeStyle != "" {
			value += ColorReset
		}
		lines = append(lines, value)
	}
	if len(lines) == 0 {
		return []string{""}
	}
	return lines
}

func tokenizeDisplayText(text string) []displayToken {
	tokens := make([]displayToken, 0, len(text))
	for offset := 0; offset < len(text); {
		if text[offset] == '\x1b' {
			if match := ansiRegex.FindStringIndex(text[offset:]); match != nil && match[0] == 0 {
				sequence := text[offset : offset+match[1]]
				tokens = append(tokens, displayToken{raw: sequence, ansi: true})
				offset += match[1]
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(text[offset:])
		if size == 0 {
			break
		}
		if unicode.IsSpace(r) {
			tokens = append(tokens, displayToken{raw: " ", whitespace: true})
		} else {
			tokens = append(tokens, displayToken{raw: string(r), width: runeWidth(r)})
		}
		offset += size
	}
	return tokens
}

func updateANSIStyle(active, sequence string) string {
	if !strings.HasPrefix(sequence, "\x1b[") || !strings.HasSuffix(sequence, "m") {
		return active
	}
	params := strings.TrimSuffix(strings.TrimPrefix(sequence, "\x1b["), "m")
	parts := strings.Split(params, ";")
	reset := false
	for _, part := range parts {
		if part == "" || part == "0" {
			reset = true
			break
		}
	}
	if reset {
		active = ""
	}
	if params != "" && params != "0" {
		active += sequence
	}
	return active
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
	// Combining marks, variation selectors, and the zero-width joiner do not
	// consume a terminal cell on their own.
	if unicode.Is(unicode.Mn, r) || unicode.Is(unicode.Me, r) || r == 0x200D ||
		(r >= 0xFE00 && r <= 0xFE0F) || (r >= 0xE0100 && r <= 0xE01EF) ||
		(r >= 0x1F3FB && r <= 0x1F3FF) {
		return 0
	}
	// Common wide CJK, full-width, and emoji ranges occupy two terminal cells.
	if (r >= 0x1100 && r <= 0x115F) ||
		r == 0x2329 || r == 0x232A ||
		(r >= 0x2E80 && r <= 0xA4CF) ||
		(r >= 0xAC00 && r <= 0xD7A3) ||
		(r >= 0xF900 && r <= 0xFAFF) ||
		(r >= 0xFE10 && r <= 0xFE19) ||
		(r >= 0xFE30 && r <= 0xFE6F) ||
		(r >= 0xFF00 && r <= 0xFF60) ||
		(r >= 0xFFE0 && r <= 0xFFE6) ||
		(r >= 0x1F300 && r <= 0x1FAFF) ||
		(r >= 0x2600 && r <= 0x26FF) ||
		(r >= 0x2700 && r <= 0x27BF) ||
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
