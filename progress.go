package main

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// progressUpdateInterval is slow enough to stay out of the way of the result
// cards but fast enough that the counter feels live.
const progressUpdateInterval = 100 * time.Millisecond

var spinnerFrames = []string{"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"}

// scanProgress is the active scan's tracker. Workers report completions here;
// it stays nil for JSON/manual runs where no bar is shown.
var scanProgress *progressTracker

// scanBar is the active bar, used by the card renderer to clear the live line
// before printing so the two never collide.
var scanBar *progressBar

// progressTracker owns the live counters for a bulk scan. The producer records
// unique targets as it discovers them; each worker records a completion.
// Values are atomic because the producer, workers, and renderer run in
// different goroutines.
type progressTracker struct {
	completed   atomic.Int64
	discovered  atomic.Int64
	producerEnd atomic.Bool
}

func (p *progressTracker) addTarget() {
	p.discovered.Add(1)
}

func (p *progressTracker) complete() {
	p.completed.Add(1)
}

func (p *progressTracker) producerFinished() {
	p.producerEnd.Store(true)
}

// snapshot returns completed, total, and whether the final total is known.
// The bar only calls this with a non-nil tracker.
func (p *progressTracker) snapshot() (done, total int64, producerDone bool) {
	done = p.completed.Load()
	total = p.discovered.Load()
	producerDone = p.producerEnd.Load()
	return
}

// progressBar renders a single status line and redraws it in place until stop.
// It is deliberately quiet: one line, one spinner, one bar, no colour beyond
// the palette already used by the rest of the tool.
type progressBar struct {
	tracker *progressTracker
	stop    chan struct{}
	stopped chan struct{}
	animate bool
	width   int
	once    sync.Once

	mu     sync.Mutex
	paused bool
	shown  bool // whether a bar is currently on screen
}

func newProgressBar(tracker *progressTracker) *progressBar {
	return &progressBar{
		tracker: tracker,
		stop:    make(chan struct{}),
		stopped: make(chan struct{}),
		animate: progressAnimationAllowed(),
		width:   terminalWidth(),
	}
}

func (b *progressBar) start() {
	go func() {
		defer close(b.stopped)
		ticker := time.NewTicker(progressUpdateInterval)
		defer ticker.Stop()
		frame := 0
		for {
			select {
			case <-b.stop:
				b.render(frame, true)
				return
			case <-ticker.C:
				if b.animate {
					frame = (frame + 1) % len(spinnerFrames)
				}
				b.render(frame, false)
			}
		}
	}()
}

func (b *progressBar) render(frame int, final bool) {
	b.mu.Lock()
	if b.paused && !final {
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()

	done, total, producerDone := b.tracker.snapshot()
	if total == 0 {
		total = done // no crawl has started yet, avoid a bogus "0 / 0"
	}
	finished := final || (producerDone && done >= total)

	line := b.compose(done, total, finished, frame)

	stdoutMutex.Lock()
	defer stdoutMutex.Unlock()
	if final {
		fmt.Fprint(os.Stdout, "\r\x1b[2K"+line+"\n")
		b.mu.Lock()
		b.shown = false
		b.mu.Unlock()
		return
	}
	fmt.Fprint(os.Stdout, "\r\x1b[2K"+line)
	b.mu.Lock()
	b.shown = true
	b.mu.Unlock()
}

// pauseForCard clears the live line and holds the renderer off while a result
// card prints, so the bar never shares a row with the card's top border.
func (b *progressBar) pauseForCard() {
	b.mu.Lock()
	b.paused = true
	wasShown := b.shown
	b.shown = false
	b.mu.Unlock()

	if wasShown {
		stdoutMutex.Lock()
		fmt.Fprint(os.Stdout, "\r\x1b[2K")
		stdoutMutex.Unlock()
	}
}

func (b *progressBar) resumeAfterCard() {
	b.mu.Lock()
	b.paused = false
	b.mu.Unlock()
}

func (b *progressBar) compose(done, total int64, finished bool, frame int) string {
	percent := 0
	if total > 0 {
		percent = int(done * 100 / total)
		if percent > 100 {
			percent = 100
		}
	}

	count := fmt.Sprintf("%d of %d", done, total)
	label := "SCANNING"
	if finished {
		label = "DONE"
	}

	left := label + " "
	if b.animate {
		left += spinnerFrames[frame] + " "
	}
	text := left + count

	// The bar is secondary information; drop it before the numbers when space
	// is tight. Nothing may wrap past the terminal edge.
	barBudget := b.width - visibleLength(text) - 12 // " [100%]" plus padding
	if barBudget > 24 {
		barBudget = 24
	}
	if barBudget >= 8 {
		filled := int(int64(barBudget) * int64(percent) / 100)
		if filled > barBudget {
			filled = barBudget
		}
		bar := strings.Repeat("#", filled) + strings.Repeat("-", barBudget-filled)
		text += " [" + bar + "]"
	}
	text += fmt.Sprintf(" %3d%%", percent)

	return truncateANSI(text, b.width)
}

func (b *progressBar) stopBar() {
	b.once.Do(func() {
		close(b.stop)
		<-b.stopped
	})
}

// progressEnabled reports whether a live bar makes sense for this run. Piped
// output and JSON mode must stay machine-readable, and a single manual lookup
// has no queue to measure.
func progressEnabled(jsonMode bool, manual bool) bool {
	if jsonMode || manual {
		return false
	}
	stat, err := os.Stdout.Stat()
	if err != nil {
		return false
	}
	return stat.Mode()&os.ModeCharDevice != 0
}

func progressAnimationAllowed() bool {
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	// CI and "no colour" requests still get a progress line, just without the
	// moving glyph, so captured logs stay stable.
	return os.Getenv("NO_COLOR") == ""
}

func truncateANSI(s string, width int) string {
	if width < 1 {
		return ""
	}
	var out strings.Builder
	cells := 0
	for offset := 0; offset < len(s); {
		if s[offset] == '\x1b' {
			if match := ansiRegex.FindStringIndex(s[offset:]); match != nil && match[0] == 0 {
				seq := s[offset : offset+match[1]]
				out.WriteString(seq)
				offset += match[1]
				continue
			}
		}
		r, size := utf8.DecodeRuneInString(s[offset:])
		if size == 0 {
			break
		}
		w := runeWidth(r)
		if cells+w > width {
			break
		}
		out.WriteString(s[offset : offset+size])
		cells += w
		offset += size
	}
	return out.String()
}
