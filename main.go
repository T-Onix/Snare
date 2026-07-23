package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"sync"
)

func main() {
	singleDomain := flag.String("d", "", "Single target domain or URL")
	filePath := flag.String("f", "", "File containing list of targets")
	outputPath := flag.String("o", "", "File to save raw results (without UI elements)")
	concurrency := flag.Int("c", 10, "Number of concurrent workers")
	noBanner := flag.Bool("no-banner", false, "Disable startup ASCII banner")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "SNARE - Web Technology Fingerprinting & CVE Discovery Engine\n")
		fmt.Fprintf(os.Stderr, "\nUsage:\n")
		fmt.Fprintf(os.Stderr, "  snare [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if !*noBanner {
		printBanner()
	}

	if *outputPath != "" {
		if err := initOutputFile(*outputPath); err != nil {
			fmt.Fprintf(os.Stderr, "[-] Failed to open output file: %v\n", err)
			os.Exit(1)
		}
		defer closeOutputFile()
	}

	if err := initScanner(); err != nil {
		fmt.Fprintf(os.Stderr, "[-] Failed to initialize scanner engine: %v\n", err)
		os.Exit(1)
	}

	targetsChan := make(chan string, 100)
	var wg sync.WaitGroup

	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go worker(targetsChan, &wg)
	}

	go func() {
		if *singleDomain != "" {
			targetsChan <- strings.TrimSpace(*singleDomain)
		}

		if *filePath != "" {
			file, err := os.Open(*filePath)
			if err == nil {
				scanner := bufio.NewScanner(file)
				for scanner.Scan() {
					if text := strings.TrimSpace(scanner.Text()); text != "" {
						targetsChan <- text
					}
				}
				file.Close()
			}
		}

		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if text := strings.TrimSpace(scanner.Text()); text != "" {
					targetsChan <- text
				}
			}
		}

		close(targetsChan)
	}()

	wg.Wait()
}

func worker(targets <-chan string, wg *sync.WaitGroup) {
	defer wg.Done()
	for target := range targets {
		processTarget(target)
	}
}
