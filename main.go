package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
)

var (
	retryCount     int
	vulnOnly       bool
	specificCVESet map[string]struct{}
)

func main() {
	singleDomain := flag.String("d", "", "Single target domain or URL")
	filePath := flag.String("f", "", "File containing list of targets")
	manualTech := flag.String("t", "", "Manual technology & version lookup (e.g. nextjs:1.2.3 or apache:2.4.49)")
	specificCVEs := flag.String("sc", "", "Comma-separated list of specific CVEs to scan for (e.g. 'CVE-2021-41773,CVE-2014-0160')")
	outputPath := flag.String("o", "", "File to save results")
	jsonOutput := flag.Bool("json", false, "Output results as structured JSON lines")
	concurrency := flag.Int("c", 10, "Number of concurrent target workers")
	retries := flag.Int("rt", 2, "Number of retries for failed target requests")
	insecureTLS := flag.Bool("k", false, "Skip TLS certificate verification (use only when required)")

	voFlag := flag.Bool("vo", false, "Only display targets with version-matched CVEs")
	noBanner := flag.Bool("no-banner", false, "Disable startup ASCII banner")
	updateCmd := flag.Bool("update", false, "Update SNARE to the latest version via go install")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SNARE - Web Technology Fingerprinting & CVE Discovery Engine\n")
		fmt.Fprintf(os.Stderr, "\nUsage:\n  snare [flags]\n\nFlags:\n")
		flag.VisitAll(func(f *flag.Flag) {
			name, usage := flag.UnquoteUsage(f)
			line := "  -" + f.Name
			if name != "" {
				line += " " + name
			}
			fmt.Fprintf(os.Stderr, "%s\n    \t%s%s\n", line, usage, flagDefaultSuffix(f))
		})
	}
	flag.Parse()

	if *updateCmd {
		fmt.Println("[+] Updating SNARE to the latest version...")
		cmd := exec.Command("go", "install", "github.com/t-onix/snare@latest")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Update failed: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("[+] SNARE updated successfully!")
		return
	}

	if *concurrency < 1 {
		fmt.Fprintln(os.Stderr, "[-] -c must be at least 1")
		os.Exit(2)
	}
	if *concurrency > 512 {
		fmt.Fprintln(os.Stderr, "[-] -c cannot exceed 512 workers")
		os.Exit(2)
	}
	if *retries < 0 {
		fmt.Fprintln(os.Stderr, "[-] -rt cannot be negative")
		os.Exit(2)
	}

	rawFilter := strings.TrimSpace(*specificCVEs)
	if rawFilter != "" {
		parsedSet, err := parseSpecificCVEFilter(rawFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid -sc value: %v\n", err)
			os.Exit(2)
		}
		specificCVESet = parsedSet
	}

	retryCount = *retries
	vulnOnly = *voFlag || len(specificCVESet) > 0
	setJSONMode(*jsonOutput)

	if !*noBanner && !*jsonOutput {
		printBanner()
	}
	if *outputPath != "" {
		if err := initOutputFile(*outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open output file: %v\n", err)
			os.Exit(1)
		}
		defer closeOutputFile()
	}

	if err := initScanner(*insecureTLS); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to initialize scanner engine: %v\n", err)
		os.Exit(1)
	}

	if *manualTech != "" {
		for _, item := range strings.Split(*manualTech, ",") {
			processManualTech(strings.TrimSpace(item))
		}
		return
	}

	queueSize := *concurrency * 4
	if queueSize < 100 {
		queueSize = 100
	}
	targetsChan := make(chan string, queueSize)
	var workers sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		workers.Add(1)
		go worker(targetsChan, &workers)
	}

	tracker := &progressTracker{}
	var bar *progressBar
	if progressEnabled(*jsonOutput, false) {
		scanProgress = tracker
		bar = newProgressBar(tracker)
		scanBar = bar
		bar.start()
		defer bar.stopBar()
	}

	// A single producer streams input, so large target lists never sit in memory.
	go func() {
		defer close(targetsChan)
		if bar != nil {
			defer tracker.producerFinished()
		}
		// Dedupe across -d, -f, and stdin. One producer owns the map, so it needs
		// no lock and duplicates never take a worker slot.
		seenTargets := make(map[string]struct{})
		if target := strings.TrimSpace(*singleDomain); target != "" {
			queueUniqueTarget(target, targetsChan, seenTargets, tracker)
		}
		if *filePath != "" {
			file, err := os.Open(*filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Cannot open target file %q: %v\n", *filePath, err)
			} else {
				if err := streamTargets(file, targetsChan, seenTargets, tracker); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Error reading target file %q: %v\n", *filePath, err)
				}
				if err := file.Close(); err != nil {
					fmt.Fprintf(os.Stderr, "[-] Error closing target file %q: %v\n", *filePath, err)
				}
			}
		}

		stat, err := os.Stdin.Stat()
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Cannot inspect stdin: %v\n", err)
			return
		}
		if stat.Mode()&os.ModeCharDevice == 0 {
			if err := streamTargets(os.Stdin, targetsChan, seenTargets, tracker); err != nil && !errors.Is(err, os.ErrClosed) {
				fmt.Fprintf(os.Stderr, "[-] Error reading stdin: %v\n", err)
			}
		}
	}()

	workers.Wait()
}

func flagDefaultSuffix(f *flag.Flag) string {
	if f.DefValue == "" || f.DefValue == "false" || f.DefValue == "0" {
		return ""
	}
	if getter, ok := f.Value.(flag.Getter); ok {
		if _, isString := getter.Get().(string); isString {
			return fmt.Sprintf(" (default %q)", f.DefValue)
		}
	}
	return fmt.Sprintf(" (default %s)", f.DefValue)
}

func streamTargets(input *os.File, out chan<- string, seen map[string]struct{}, trackers ...*progressTracker) error {
	scanner := bufio.NewScanner(input)
	// Some generated target lists exceed the scanner's 64 KiB default line limit.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		queueUniqueTarget(scanner.Text(), out, seen, trackers...)
	}
	return scanner.Err()
}

func queueUniqueTarget(raw string, out chan<- string, seen map[string]struct{}, trackers ...*progressTracker) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return
	}
	key := strings.TrimSuffix(strings.ToLower(target), "/")
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	for _, tracker := range trackers {
		if tracker != nil {
			tracker.addTarget()
		}
	}
	out <- target
}

func worker(targets <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range targets {
		processTarget(target)
	}
}
