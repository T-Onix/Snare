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
	specificCVEsLong := flag.String("specific-cves", "", "Comma-separated list of specific CVEs to scan for")
	outputPath := flag.String("o", "", "File to save results")
	jsonOutput := flag.Bool("json", false, "Output results as structured JSON lines")
	concurrency := flag.Int("c", 10, "Number of concurrent target workers")
	retries := flag.Int("rt", 2, "Number of retries for failed target requests")
	insecureTLS := flag.Bool("k", false, "Skip TLS certificate verification (use only when required)")

	vulnOnlyFlag := flag.Bool("vuln-only", false, "Only display targets with version-matched CVEs")
	voFlag := flag.Bool("vo", false, "Only display targets with version-matched CVEs (shorthand)")
	noBanner := flag.Bool("no-banner", false, "Disable startup ASCII banner")
	updateCmd := flag.Bool("update", false, "Update SNARE to the latest version via go install")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SNARE - Web Technology Fingerprinting & CVE Discovery Engine\n")
		fmt.Fprintf(os.Stderr, "\nUsage:\n  snare [flags]\n\nFlags:\n")
		flag.PrintDefaults()
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
	if *specificCVEsLong != "" {
		if rawFilter != "" {
			rawFilter += "," + *specificCVEsLong
		} else {
			rawFilter = *specificCVEsLong
		}
	}
	if rawFilter != "" {
		parsedSet, err := parseSpecificCVEFilter(rawFilter)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[-] Invalid -sc / -specific-cves value: %v\n", err)
			os.Exit(2)
		}
		specificCVESet = parsedSet
	}

	retryCount = *retries
	vulnOnly = *vulnOnlyFlag || *voFlag || len(specificCVESet) > 0
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

	// A dedicated producer streams input, so large target lists are not kept in memory.
	go func() {
		defer close(targetsChan)
		// Avoid scanning the exact same target more than once when the user
		// combines -d, -f, and piped stdin. This map lives in the single producer,
		// so it needs no mutex and duplicates never occupy worker queue slots.
		seenTargets := make(map[string]struct{})
		if target := strings.TrimSpace(*singleDomain); target != "" {
			queueUniqueTarget(target, targetsChan, seenTargets)
		}
		if *filePath != "" {
			file, err := os.Open(*filePath)
			if err != nil {
				fmt.Fprintf(os.Stderr, "[-] Cannot open target file %q: %v\n", *filePath, err)
			} else {
				if err := streamTargets(file, targetsChan, seenTargets); err != nil {
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
			if err := streamTargets(os.Stdin, targetsChan, seenTargets); err != nil && !errors.Is(err, os.ErrClosed) {
				fmt.Fprintf(os.Stderr, "[-] Error reading stdin: %v\n", err)
			}
		}
	}()

	workers.Wait()
}

func streamTargets(input *os.File, out chan<- string, seen map[string]struct{}) error {
	scanner := bufio.NewScanner(input)
	// Scanner's default 64 KiB line limit is too small for some generated target lists.
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	for scanner.Scan() {
		queueUniqueTarget(scanner.Text(), out, seen)
	}
	return scanner.Err()
}

func queueUniqueTarget(raw string, out chan<- string, seen map[string]struct{}) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return
	}
	key := strings.TrimSuffix(strings.ToLower(target), "/")
	if _, exists := seen[key]; exists {
		return
	}
	seen[key] = struct{}{}
	out <- target
}

func worker(targets <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range targets {
		processTarget(target)
	}
}
