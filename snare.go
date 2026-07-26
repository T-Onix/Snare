package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

type TechMatch struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type CVEInfo struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity"`
	CVSS     float64 `json:"cvss,omitempty"`
	HasPoC   bool    `json:"has_poc"`
	Summary  string  `json:"summary"`
}

type TechResult struct {
	Tech TechMatch `json:"tech"`
	CVEs []CVEInfo `json:"cves,omitempty"`
}

var (
	httpClient       *http.Client
	wappalyzerClient *wappalyzer.Wappalyze

	knownCoreCVEs = map[string][]struct {
		MaxVersion string
		CVE        string
		Severity   string
		CVSS       float64
		HasPoC     bool
		Summary    string
	}{
		"apache": {
			{"2.4.25", "CVE-2017-9798", "HIGH", 7.5, true, "OptionsBleed: Memory disclosure in OPTIONS HTTP method"},
			{"2.4.25", "CVE-2017-7679", "HIGH", 7.5, false, "mod_mime buffer over-read vulnerability"},
			{"2.4.25", "CVE-2017-7668", "HIGH", 7.5, false, "ap_get_basic_auth_pw() buffer over-read"},
			{"2.4.25", "CVE-2017-7659", "HIGH", 7.5, true, "mod_http2 NULL pointer dereference Denial of Service"},
			{"2.4.25", "CVE-2017-3169", "HIGH", 7.5, false, "mod_ssl NULL pointer dereference"},
			{"2.4.25", "CVE-2017-3167", "HIGH", 7.5, true, "ap_get_basic_auth_pw() authentication bypass"},
			{"2.4.49", "CVE-2021-41773", "CRITICAL", 9.8, true, "Path traversal and remote code execution in Apache 2.4.49"},
			{"2.4.50", "CVE-2021-42013", "CRITICAL", 9.8, true, "Path traversal and remote code execution fix bypass in Apache 2.4.50"},
		},
		"nginx": {
			{"1.13.2", "CVE-2017-7529", "HIGH", 7.5, true, "Nginx integer overflow in range filter leading to information disclosure"},
			{"1.20.0", "CVE-2021-23017", "HIGH", 7.7, true, "1-byte memory overwrite in resolver module"},
		},
		"php": {
			{"7.3.11", "CVE-2019-11043", "CRITICAL", 9.8, true, "php-fpm remote code execution in nginx configurations"},
			{"8.1.0", "CVE-2021-32610", "CRITICAL", 9.8, true, "PHP 8.1.0-dev backdoor / arbitrary command execution"},
		},
		"openssl": {
			{"1.0.1f", "CVE-2014-0160", "HIGH", 7.5, true, "Heartbleed: Out-of-bounds read in TLS heartbeat extension"},
			{"1.0.2g", "CVE-2016-0800", "HIGH", 7.4, true, "DROWN attack: Cross-protocol attack on SSLv2/TLS"},
			{"1.0.1k", "CVE-2015-0204", "MEDIUM", 5.9, true, "FREAK attack: RSA export keys vulnerability"},
		},
	}
)

func initScanner() error {
	var transport *http.Transport
	if dt, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = dt.Clone()
	} else {
		transport = &http.Transport{}
	}

	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 6 * time.Second

	httpClient = &http.Client{
		Timeout:   8 * time.Second,
		Transport: transport,
	}

	var err error
	wappalyzerClient, err = wappalyzer.New()
	return err
}

func processManualTech(rawInput string) {
	rawInput = strings.TrimSpace(rawInput)
	if rawInput == "" {
		return
	}

	tech := parseTechVersion(rawInput)
	if tech.Name == "" {
		return
	}

	res := TechResult{Tech: tech}
	if tech.Version != "" {
		res.CVEs = resolveVulnerabilities(tech.Name, tech.Version)
	}

	targetLabel := fmt.Sprintf("MANUAL LOOKUP [%s]", rawInput)
	renderTargetCard(targetLabel, []TechResult{res})
}

func processTarget(rawTarget string) {
	resp, finalURL := fetchTargetSmart(rawTarget)
	if resp == nil {
		return
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}

	fingerprints := wappalyzerClient.Fingerprint(resp.Header, bodyBytes)
	if len(fingerprints) == 0 {
		return
	}

	var results []TechResult

	for techRaw := range fingerprints {
		tech := parseTechVersion(techRaw)
		res := TechResult{Tech: tech}

		if tech.Version != "" {
			res.CVEs = resolveVulnerabilities(tech.Name, tech.Version)
		}
		results = append(results, res)
	}

	renderTargetCard(finalURL, results)
}

func fetchTargetSmart(rawTarget string) (*http.Response, string) {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return nil, ""
	}

	if strings.HasPrefix(rawTarget, "http://") || strings.HasPrefix(rawTarget, "https://") {
		req, err := http.NewRequest("GET", rawTarget, nil)
		if err != nil {
			return nil, ""
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Snare/1.3")
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, ""
		}
		return resp, rawTarget
	}

	httpsURL := "https://" + rawTarget
	req, err := http.NewRequest("GET", httpsURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Snare/1.3")
		resp, err := httpClient.Do(req)
		if err == nil {
			return resp, httpsURL
		}
	}

	httpURL := "http://" + rawTarget
	req, err = http.NewRequest("GET", httpURL, nil)
	if err != nil {
		return nil, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Snare/1.3")
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, ""
	}
	return resp, httpURL
}

func resolveVulnerabilities(techName, version string) []CVEInfo {
	cleanVersion := strings.TrimPrefix(strings.TrimPrefix(version, "v"), "V")
	vendor, product := normalizeTech(techName)
	seen := make(map[string]bool)
	var results []CVEInfo

	if localList, ok := knownCoreCVEs[product]; ok {
		for _, entry := range localList {
			if compareVersionsLessOrEqual(cleanVersion, entry.MaxVersion) {
				if !seen[entry.CVE] {
					seen[entry.CVE] = true
					results = append(results, CVEInfo{
						ID:       entry.CVE,
						Severity: entry.Severity,
						CVSS:     entry.CVSS,
						HasPoC:   entry.HasPoC,
						Summary:  entry.Summary,
					})
				}
			}
		}
	}

	if len(results) > 0 {
		return results
	}

	onlineCVEs := queryOnlineAPIs(vendor, product, cleanVersion)
	for _, c := range onlineCVEs {
		if !seen[c.ID] {
			seen[c.ID] = true
			results = append(results, c)
		}
	}

	return results
}

func calculateSeverityFromCVSS(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "UNKNOWN"
	}
}

func queryOnlineAPIs(vendor, product, version string) []CVEInfo {
	var cves []CVEInfo
	apiURL := fmt.Sprintf("https://vulnerability.circl.lu/api/search/%s/%s", url.PathEscape(vendor), url.PathEscape(product))
	req, err := http.NewRequest("GET", apiURL, nil)
	if err == nil {
		req.Header.Set("User-Agent", "Snare/1.3")
		resp, err := httpClient.Do(req)
		if err == nil && resp.StatusCode == 200 {
			defer resp.Body.Close()
			var items []struct {
				ID      string  `json:"id"`
				CVSS    float64 `json:"cvss"`
				Summary string  `json:"summary"`
				MapEdb  string  `json:"map_cve_exploitdb_exploitdbid,omitempty"`
				MapMsf  string  `json:"map_cve_msf_msf_script_file,omitempty"`
			}
			if json.NewDecoder(resp.Body).Decode(&items) == nil {
				for _, item := range items {
					sev := calculateSeverityFromCVSS(item.CVSS)
					hasPoc := item.MapEdb != "" || item.MapMsf != "" || strings.Contains(strings.ToLower(item.Summary), "exploit") || strings.Contains(strings.ToLower(item.Summary), "proof of concept")
					
					cves = append(cves, CVEInfo{
						ID:       item.ID,
						Severity: sev,
						CVSS:     item.CVSS,
						HasPoC:   hasPoc,
						Summary:  item.Summary,
					})
					if len(cves) >= 5 {
						break
					}
				}
			}
		}
	}
	return cves
}

func compareVersionsLessOrEqual(target, max string) bool {
	tParts := parseVersionParts(target)
	mParts := parseVersionParts(max)

	for i := 0; i < len(tParts) && i < len(mParts); i++ {
		if tParts[i] < mParts[i] {
			return true
		}
		if tParts[i] > mParts[i] {
			return false
		}
	}
	return len(tParts) <= len(mParts)
}

func parseVersionParts(v string) []int {
	parts := strings.Split(v, ".")
	var res []int
	for _, p := range parts {
		num, _ := strconv.Atoi(p)
		res = append(res, num)
	}
	return res
}

func normalizeTech(rawName string) (string, string) {
	name := strings.ToLower(strings.TrimSpace(rawName))
	switch {
	case strings.Contains(name, "apache http server"), strings.Contains(name, "apache"), strings.Contains(name, "httpd"):
		return "apache", "apache"
	case strings.Contains(name, "nginx"):
		return "nginx", "nginx"
	case strings.Contains(name, "php"):
		return "php", "php"
	case strings.Contains(name, "openssl"):
		return "openssl", "openssl"
	default:
		clean := strings.ReplaceAll(name, " ", "_")
		return clean, clean
	}
}

func parseTechVersion(raw string) TechMatch {
	if strings.Contains(raw, ":") {
		parts := strings.SplitN(raw, ":", 2)
		return TechMatch{
			Name:    strings.TrimSpace(parts[0]),
			Version: strings.TrimSpace(parts[1]),
		}
	}
	return TechMatch{
		Name:    strings.TrimSpace(raw),
		Version: "",
	}
}
