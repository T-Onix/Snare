package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
)

const (
	maxTargetBodyBytes      = 4 << 20
	maxCVEResponseBytes     = 32 << 20
	maxCVECacheEntries      = 4096
	persistentNVDCacheTTL   = 15 * time.Minute
	persistentCIRCLCacheTTL = 15 * time.Minute
	cveCacheTTL             = 5 * time.Minute
	cveErrorCacheTTL        = 20 * time.Second
)

type TechMatch struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

type CVEInfo struct {
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	CVSS       float64  `json:"cvss,omitempty"`
	HasPoC     bool     `json:"has_poc"`
	Summary    string   `json:"summary"`
	References []string `json:"references,omitempty"`
}

type TechResult struct {
	Tech      TechMatch `json:"tech"`
	CVEs      []CVEInfo `json:"cves,omitempty"`
	CVEStatus string    `json:"cve_status,omitempty"`
	CVEError  string    `json:"cve_error,omitempty"`
}

// circlRecord deliberately accepts both the legacy, backwards-compatible CIRCL
// CVE-Search fields and fields used by newer CVE 5 / NVD-shaped records.
type circlRecord struct {
	ID          string   `json:"id"`
	CVE         string   `json:"cve"`
	CVEID       string   `json:"cveId"`
	Aliases     []string `json:"aliases"`
	CVEMetadata struct {
		CVEID string `json:"cveId"`
		State string `json:"state"`
	} `json:"cveMetadata"`
	CVSS                      json.RawMessage `json:"cvss"`
	Severity                  string          `json:"severity"`
	Summary                   string          `json:"summary"`
	References                json.RawMessage `json:"references"`
	VulnerableConfiguration   []string        `json:"vulnerable_configuration"`
	VulnerableConfiguration22 []string        `json:"vulnerable_configuration_cpe_2_2"`
	VulnerableConfigurationST json.RawMessage `json:"vulnerable_configuration_st"`
	Configurations            json.RawMessage `json:"configurations"`
	Affected                  json.RawMessage `json:"affected"`
	Containers                json.RawMessage `json:"containers"`
	Metrics                   json.RawMessage `json:"metrics"`
	Descriptions              json.RawMessage `json:"descriptions"`
	CNA                       json.RawMessage `json:"cna"`
}

type cpeConfig struct {
	ID                    string `json:"id"`
	Criteria              string `json:"criteria"`
	CPE23URI              string `json:"cpe23Uri"`
	CPE22URI              string `json:"cpe22Uri"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
	Vulnerable            *bool  `json:"vulnerable"`
}

var (
	httpClient       *http.Client // short timeout for target fingerprinting
	cveHTTPClient    *http.Client // CIRCL/NVD client with bounded headers and total timeout
	osvHTTPClient    *http.Client // OSV gets its own longer header deadline; it must not inherit CIRCL's timeout
	wappalyzerClient *wappalyzer.Wappalyze

	// Identical product searches are coalesced across workers. This matters when
	// scanning hundreds/thousands of targets that expose the same software.
	cveCache = struct {
		sync.Mutex
		entries  map[string]cveCacheEntry
		inflight map[string]*cveQueryCall
	}{
		entries:  make(map[string]cveCacheEntry),
		inflight: make(map[string]*cveQueryCall),
	}
	cveAPISlots = make(chan struct{}, 4)
	// NVD is more aggressively rate-limited than CIRCL. Bound parallel calls
	// separately; a user's NVD_API_KEY can be used for higher throughput.
	nvdAPISlots  = make(chan struct{}, 2)
	nvdRateState = struct {
		sync.Mutex
		nextAllowed   time.Time
		cooldownUntil time.Time
		loaded        bool
	}{}
	circlRateState = struct {
		sync.Mutex
		cooldownUntil time.Time
		loaded        bool
	}{}

	versionTokenRE = regexp.MustCompile(`[0-9]+|[a-z]+`)
	cpeComponentRE = regexp.MustCompile(`^[a-zA-Z0-9._+~-]+$`)
)

type cveCacheEntry struct {
	records   []circlRecord
	err       error
	expiresAt time.Time
}

type cveQueryCall struct {
	done    chan struct{}
	records []circlRecord
	err     error
}

// Version-specific secondary providers (OSV and NVD) have their own bounded
// cache because their answers depend on the requested version, unlike CIRCL's
// vendor/product catalogue query.
type externalCacheEntry struct {
	cves      []CVEInfo
	err       error
	expiresAt time.Time
}
type externalQueryCall struct {
	done chan struct{}
	cves []CVEInfo
	err  error
}

var externalCVECache = struct {
	sync.Mutex
	entries  map[string]externalCacheEntry
	inflight map[string]*externalQueryCall
}{entries: make(map[string]externalCacheEntry), inflight: make(map[string]*externalQueryCall)}

// nvdDiskEntry persists successful CPE lookups across process restarts. A short
// TTL prevents Ctrl+C/re-run loops from hammering NVD without hiding updates
// for an excessive amount of time. Empty successful responses are cacheable.
type nvdDiskEntry struct {
	FetchedAt time.Time `json:"fetched_at"`
	CVEs      []CVEInfo `json:"cves"`
}

type circlDiskEntry struct {
	FetchedAt time.Time     `json:"fetched_at"`
	Records   []circlRecord `json:"records"`
}

type circlThrottleDiskState struct {
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
}

type nvdThrottleDiskState struct {
	NextAllowed   time.Time `json:"next_allowed,omitempty"`
	CooldownUntil time.Time `json:"cooldown_until,omitempty"`
}

func initScanner(insecureTLS bool) error {
	loadNVDThrottleState()
	loadCIRCLThrottleState()
	var transport *http.Transport
	if defaultTransport, ok := http.DefaultTransport.(*http.Transport); ok {
		transport = defaultTransport.Clone()
	} else {
		transport = &http.Transport{}
	}
	transport.MaxIdleConns = 200
	transport.MaxIdleConnsPerHost = 20
	transport.MaxConnsPerHost = 100 // avoid unbounded sockets with very high -c values
	transport.IdleConnTimeout = 90 * time.Second
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 6 * time.Second
	transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if insecureTLS {
		// #nosec G402 -- explicitly opted into by the operator with -k.
		transport.TLSClientConfig.InsecureSkipVerify = true
	}

	redirectPolicy := func(req *http.Request, via []*http.Request) error {
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	httpClient = &http.Client{
		Timeout:       8 * time.Second,
		Transport:     transport,
		CheckRedirect: redirectPolicy,
	}
	// CVE sources often take longer to respond than a target's HTML. Clone the
	// transport as well as the client: otherwise ResponseHeaderTimeout=6s on
	// the target transport still silently caps all CVE API requests.
	cveTransport := transport.Clone()
	cveTransport.ResponseHeaderTimeout = 5 * time.Second
	cveTransport.MaxIdleConnsPerHost = 8
	cveTransport.MaxConnsPerHost = 16
	cveHTTPClient = &http.Client{
		Timeout:       8 * time.Second,
		Transport:     cveTransport,
		CheckRedirect: redirectPolicy,
	}

	// OSV normally responds quickly, but its shared POST endpoint can have
	// occasional cold-start / transient header latency. Do not let the tighter
	// CIRCL/NVD header deadline turn those cases into false lookup failures.
	osvTransport := transport.Clone()
	osvTransport.ResponseHeaderTimeout = 12 * time.Second
	osvTransport.MaxIdleConnsPerHost = 8
	osvTransport.MaxConnsPerHost = 16
	osvHTTPClient = &http.Client{
		Timeout:       15 * time.Second,
		Transport:     osvTransport,
		CheckRedirect: redirectPolicy,
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
	if tech.Version == "" {
		res.CVEStatus = "version_unknown"
	} else {
		res.CVEs, res.CVEStatus, res.CVEError = lookupVulnerabilitiesDetailed(tech.Name, tech.Version)
	}
	if vulnOnly && len(res.CVEs) == 0 {
		return
	}

	renderTargetCard(fmt.Sprintf("MANUAL LOOKUP [%s]", rawInput), []TechResult{res})
}

func processTarget(rawTarget string) {
	resp, finalURL := fetchTargetSmart(rawTarget)
	if resp == nil {
		return
	}
	defer resp.Body.Close()
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}

	// A response body can be arbitrarily large. Fingerprinting needs only the
	// beginning of a response, so cap decompressed reads to keep memory bounded.
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxTargetBodyBytes))
	if err != nil {
		return
	}

	fingerprints := wappalyzerClient.Fingerprint(resp.Header, bodyBytes)
	if len(fingerprints) == 0 {
		return
	}

	techNames := make([]string, 0, len(fingerprints))
	for techRaw := range fingerprints {
		techNames = append(techNames, techRaw)
	}
	sort.Strings(techNames) // stable ordering within a target

	results := make([]TechResult, 0, len(techNames))
	hasCVE := false
	for _, techRaw := range techNames {
		tech := parseTechVersion(techRaw)
		res := TechResult{Tech: tech}
		if tech.Version == "" {
			res.CVEStatus = "version_unknown"
		} else {
			res.CVEs, res.CVEStatus, res.CVEError = lookupVulnerabilitiesDetailed(tech.Name, tech.Version)
		}
		if len(res.CVEs) > 0 {
			hasCVE = true
		}
		if !vulnOnly || len(res.CVEs) > 0 {
			results = append(results, res)
		}
	}

	if vulnOnly && !hasCVE {
		return
	}
	if len(results) > 0 {
		renderTargetCard(finalURL, results)
	}
}

func fetchTargetSmart(rawTarget string) (*http.Response, string) {
	rawTarget = strings.TrimSpace(rawTarget)
	if rawTarget == "" {
		return nil, ""
	}

	lower := strings.ToLower(rawTarget)
	if strings.HasPrefix(lower, "http://") || strings.HasPrefix(lower, "https://") {
		resp := doRequestWithRetry(rawTarget)
		if resp == nil {
			return nil, ""
		}
		return resp, rawTarget
	}

	httpsURL := "https://" + rawTarget
	if resp := doRequestWithRetry(httpsURL); resp != nil {
		return resp, httpsURL
	}

	httpURL := "http://" + rawTarget
	if resp := doRequestWithRetry(httpURL); resp != nil {
		return resp, httpURL
	}
	return nil, ""
}

func doRequestWithRetry(targetURL string) *http.Response {
	attempts := retryCount + 1
	for i := 0; i < attempts; i++ {
		req, err := http.NewRequest(http.MethodGet, targetURL, nil)
		if err != nil {
			return nil
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; SNARE/1.6.5; +https://github.com/t-onix/snare)")
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")

		resp, err := httpClient.Do(req)
		if err == nil {
			return resp
		}
		if i < attempts-1 {
			time.Sleep(time.Duration(i+1) * 200 * time.Millisecond)
		}
	}
	return nil
}

// resolveVulnerabilities remains as a simple helper for callers that only need
// the result slice. LookupStatus is used by the CLI so a source outage is never
// presented as a clean bill of health.
func resolveVulnerabilities(techName, version string) []CVEInfo {
	cves, _ := lookupVulnerabilities(techName, version)
	return cves
}

func lookupVulnerabilities(techName, version string) ([]CVEInfo, string) {
	cves, status, _ := lookupVulnerabilitiesDetailed(techName, version)
	return cves, status
}

func lookupVulnerabilitiesDetailed(techName, version string) ([]CVEInfo, string, string) {
	cleanVersion := cleanVersionString(version)
	if cleanVersion == "" {
		return nil, "version_unknown", ""
	}
	vendor, product := normalizeTech(techName)
	if vendor == "" || product == "" {
		return nil, "unsupported_product", ""
	}

	// Query CIRCL and the version-aware OSV API concurrently. Previously, a
	// CIRCL DNS/timeout failure stopped all further lookup attempts, which is
	// exactly why Bootstrap/jQuery/Drupal displayed LOOKUP UNAVAILABLE.
	type circlResult struct {
		records []circlRecord
		err     error
	}
	type osvResult struct {
		supported bool
		cves      []CVEInfo
		err       error
	}
	circlCh := make(chan circlResult, 1)
	osvCh := make(chan osvResult, 1)
	go func() {
		records, err := getProductCVEs(vendor, product)
		circlCh <- circlResult{records: records, err: err}
	}()
	go func() {
		cves, supported, err := lookupOSVVersion(vendor, product, cleanVersion)
		osvCh <- osvResult{supported: supported, cves: cves, err: err}
	}()

	circl := <-circlCh
	osv := <-osvCh

	results := make([]CVEInfo, 0, len(circl.records)+len(osv.cves)+4)
	seen := make(map[string]struct{})
	appendCVE := func(cve CVEInfo) {
		id := strings.ToUpper(strings.TrimSpace(cve.ID))
		if id == "" {
			return
		}
		if _, exists := seen[id]; exists {
			return
		}
		seen[id] = struct{}{}
		cve.ID = id
		results = append(results, cve)
	}
	for _, record := range circl.records {
		id := canonicalCVEID(record)
		if id == "" || isRejectedCVERecord(record) || !recordAffectsVersion(record, vendor, product, cleanVersion) {
			continue
		}
		cvss := extractCVSS(record.CVSS)
		if cvss <= 0 {
			cvss = extractCVSS(record.Metrics)
		}
		if cvss <= 0 {
			cvss = extractCVSS(record.Containers)
		}
		if cvss <= 0 {
			cvss = extractCVSS(record.CNA)
		}
		severity := strings.ToUpper(strings.TrimSpace(record.Severity))
		if severity == "" || severity == "NONE" {
			severity = calculateSeverityFromCVSS(cvss)
		}
		summary := strings.TrimSpace(record.Summary)
		if summary == "" {
			summary = extractDescription(record.Descriptions, record.CNA, record.Containers)
		}
		refs := uniqueStrings(extractReferences(record.References, record.Containers, record.CNA))
		appendCVE(CVEInfo{ID: id, Severity: severity, CVSS: cvss, HasPoC: hasPublicPoCReference(refs), Summary: summary, References: refs})
	}
	for _, cve := range osv.cves {
		appendCVE(cve)
	}

	// NVD is a third independent source. Try it whenever the first two sources
	// produced no version-matched CVE, including a successful-but-empty OSV
	// response. The previous condition skipped NVD precisely when OSV was
	// reachable but had no record for a package/version, turning a normal
	// no-match into a false lookup failure. The version-specific cache and the
	// NVD semaphore below keep this fallback bounded during large scans.
	nvdAttempted, nvdOK := false, false
	var nvdErr error
	if len(results) == 0 && nvdCPEName(vendor, product, cleanVersion) != "" {
		nvdAttempted = true
		nvdCVEs, err := lookupNVDVersion(vendor, product, cleanVersion)
		nvdErr = err
		nvdOK = err == nil
		if err == nil {
			for _, cve := range nvdCVEs {
				appendCVE(cve)
			}
		}
	}

	// Record errors even when another provider returns findings, so output never
	// silently implies that every source was consulted successfully.
	circlOK := circl.err == nil
	osvOK := osv.supported && osv.err == nil
	var errorsFound []string
	if circl.err != nil {
		errorsFound = append(errorsFound, "CIRCL: "+circl.err.Error())
	}
	if osv.supported && osv.err != nil {
		errorsFound = append(errorsFound, "OSV: "+osv.err.Error())
	}
	if nvdAttempted && nvdErr != nil {
		errorsFound = append(errorsFound, "NVD: "+nvdErr.Error())
	}
	diagnostic := strings.Join(errorsFound, "; ")

	// Always merge the small offline list as a last-resort safety net. These
	// results are labelled in UI by status and must still be checked for distro
	// backports and configuration-dependent applicability.
	usedFallback := false
	for _, cve := range offlineFallbackCVEs(vendor, product, cleanVersion) {
		if _, exists := seen[strings.ToUpper(cve.ID)]; exists {
			continue
		}
		appendCVE(cve)
		usedFallback = true
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].CVSS != results[j].CVSS {
			return results[i].CVSS > results[j].CVSS
		}
		return results[i].ID < results[j].ID
	})
	if len(results) > 0 {
		if usedFallback {
			return results, "bundled_fallback", diagnostic
		}
		if diagnostic != "" {
			return results, "matched_partial", diagnostic
		}
		return results, "matched", ""
	}

	// A clean 200 response with an empty result set is NOT a lookup failure.
	// Mark the lookup unavailable only when every source we could use failed.
	if circlOK || osvOK || nvdOK {
		if diagnostic != "" {
			return results, "partial_lookup", diagnostic
		}
		return results, "checked_no_match", ""
	}
	return results, "lookup_error", diagnostic
}

// cacheExternalCVEs caches success (including no-match responses) for five
// minutes and failures for twenty seconds, and coalesces duplicate in-flight
// queries. This is important when thousands of hosts expose the same library.
func cacheExternalCVEs(key string, loader func() ([]CVEInfo, error)) ([]CVEInfo, error) {
	now := time.Now()
	externalCVECache.Lock()
	if entry, ok := externalCVECache.entries[key]; ok && now.Before(entry.expiresAt) {
		cves, err := append([]CVEInfo(nil), entry.cves...), entry.err
		externalCVECache.Unlock()
		return cves, err
	}
	if call, ok := externalCVECache.inflight[key]; ok {
		externalCVECache.Unlock()
		<-call.done
		return append([]CVEInfo(nil), call.cves...), call.err
	}
	call := &externalQueryCall{done: make(chan struct{})}
	externalCVECache.inflight[key] = call
	externalCVECache.Unlock()

	cves, err := loader()
	ttl := cveCacheTTL
	if err != nil {
		ttl = cveErrorCacheTTL
	}
	now = time.Now()
	externalCVECache.Lock()
	call.cves, call.err = append([]CVEInfo(nil), cves...), err
	if len(externalCVECache.entries) >= maxCVECacheEntries {
		for cachedKey, entry := range externalCVECache.entries {
			if !now.Before(entry.expiresAt) {
				delete(externalCVECache.entries, cachedKey)
			}
		}
	}
	if len(externalCVECache.entries) < maxCVECacheEntries || externalCVECache.entries[key].expiresAt.IsZero() {
		externalCVECache.entries[key] = externalCacheEntry{cves: append([]CVEInfo(nil), cves...), err: err, expiresAt: now.Add(ttl)}
	}
	delete(externalCVECache.inflight, key)
	close(call.done)
	externalCVECache.Unlock()
	return append([]CVEInfo(nil), cves...), err
}

// lookupOSVVersion maps known public library fingerprints to exact package
// coordinates. OSV is queried only when the detected version has at least a
// major/minor component; manual affected-range validation guards against fuzzy
// upstream matching.
func lookupOSVVersion(vendor, product, version string) ([]CVEInfo, bool, error) {
	name, ecosystem, ok := osvPackageFor(vendor, product)
	if !ok || !strings.Contains(version, ".") {
		return nil, false, nil
	}
	key := "osv/" + ecosystem + "/" + name + "@" + version
	cves, err := cacheExternalCVEs(key, func() ([]CVEInfo, error) {
		return queryOSVPackage(name, ecosystem, version)
	})
	return cves, true, err
}

func osvPackageFor(vendor, product string) (name, ecosystem string, ok bool) {
	switch product {
	case "bootstrap":
		return "bootstrap", "npm", true
	case "jquery":
		return "jquery", "npm", true
	case "drupal":
		return "drupal/core", "Packagist", true
	default:
		return "", "", false
	}
}

type osvQueryRequest struct {
	Package struct {
		Name      string `json:"name"`
		Ecosystem string `json:"ecosystem"`
	} `json:"package"`
	Version string `json:"version"`
}
type osvVulnerability struct {
	ID         string   `json:"id"`
	Aliases    []string `json:"aliases"`
	Summary    string   `json:"summary"`
	Details    string   `json:"details"`
	References []struct {
		URL string `json:"url"`
	} `json:"references"`
	Affected []struct {
		Package struct {
			Name      string `json:"name"`
			Ecosystem string `json:"ecosystem"`
		} `json:"package"`
		Versions []string `json:"versions"`
		Ranges   []struct {
			Type   string              `json:"type"`
			Events []map[string]string `json:"events"`
		} `json:"ranges"`
	} `json:"affected"`
	Severity []struct {
		Type  string `json:"type"`
		Score string `json:"score"`
	} `json:"severity"`
}

func queryOSVPackage(name, ecosystem, version string) ([]CVEInfo, error) {
	payload := osvQueryRequest{Version: version}
	payload.Package.Name, payload.Package.Ecosystem = name, ecosystem
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, "https://api.osv.dev/v1/query", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SNARE/1.6.6 (+https://github.com/t-onix/snare)")
	client := osvHTTPClient
	if client == nil {
		// Keep tests and non-main callers safe if they construct the scanner
		// without initScanner; production always initializes osvHTTPClient.
		client = cveHTTPClient
	}
	if client == nil {
		return nil, fmt.Errorf("OSV client is not initialized")
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OSV request (15s deadline): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("OSV returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCVEResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCVEResponseBytes {
		return nil, fmt.Errorf("OSV response exceeded %d bytes", maxCVEResponseBytes)
	}
	var response struct {
		Vulns []osvVulnerability `json:"vulns"`
	}
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode OSV response: %w", err)
	}
	results := make([]CVEInfo, 0, len(response.Vulns))
	for _, vuln := range response.Vulns {
		if !osvAffectsPackageVersion(vuln, name, ecosystem, version) {
			continue
		}
		id := preferredOSVIdentifier(vuln)
		if id == "" {
			continue
		}
		summary := strings.TrimSpace(vuln.Summary)
		if summary == "" {
			summary = strings.TrimSpace(vuln.Details)
		}
		refs := make([]string, 0, len(vuln.References))
		for _, ref := range vuln.References {
			refs = append(refs, ref.URL)
		}
		refs = uniqueStrings(refs)
		results = append(results, CVEInfo{ID: id, Severity: "UNKNOWN", Summary: summary, HasPoC: hasPublicPoCReference(refs), References: refs})
	}
	return results, nil
}

func preferredOSVIdentifier(vuln osvVulnerability) string {
	for _, alias := range vuln.Aliases {
		alias = strings.ToUpper(strings.TrimSpace(alias))
		if strings.HasPrefix(alias, "CVE-") {
			return alias
		}
	}
	if id := strings.ToUpper(strings.TrimSpace(vuln.ID)); strings.HasPrefix(id, "CVE-") {
		return id
	}
	if id := strings.ToUpper(strings.TrimSpace(vuln.ID)); id != "" {
		return id
	}
	return ""
}

func osvAffectsPackageVersion(vuln osvVulnerability, name, ecosystem, version string) bool {
	for _, affected := range vuln.Affected {
		if !strings.EqualFold(affected.Package.Name, name) || !strings.EqualFold(affected.Package.Ecosystem, ecosystem) {
			continue
		}
		for _, affectedVersion := range affected.Versions {
			if cleanVersionString(affectedVersion) == cleanVersionString(version) {
				return true
			}
		}
		for _, versionRange := range affected.Ranges {
			if !strings.EqualFold(versionRange.Type, "SEMVER") && !strings.EqualFold(versionRange.Type, "ECOSYSTEM") {
				continue
			}
			introduced := ""
			for _, event := range versionRange.Events {
				if v := event["introduced"]; v != "" {
					introduced = v
					continue
				}
				if fixed := event["fixed"]; fixed != "" {
					if introduced != "" && (introduced == "0" || compareVersions(version, introduced) >= 0) && compareVersions(version, fixed) < 0 {
						return true
					}
					introduced = ""
					continue
				}
				if last := event["last_affected"]; last != "" {
					if introduced != "" && (introduced == "0" || compareVersions(version, introduced) >= 0) && compareVersions(version, last) <= 0 {
						return true
					}
					introduced = ""
					continue
				}
				if limit := event["limit"]; limit != "" {
					if introduced != "" && (introduced == "0" || compareVersions(version, introduced) >= 0) && compareVersions(version, limit) < 0 {
						return true
					}
					introduced = ""
				}
			}
			if introduced != "" && (introduced == "0" || compareVersions(version, introduced) >= 0) {
				return true
			}
		}
	}
	return false
}

// lookupNVDVersion asks NVD to correlate a concrete CPE and version. NVD's
// own version-range matching is used here, avoiding unsafe broad keyword
// results and allowing major-only fingerprints such as Drupal 10 to be queried.
func lookupNVDVersion(vendor, product, version string) ([]CVEInfo, error) {
	cpe := nvdCPEName(vendor, product, version)
	if cpe == "" {
		return nil, fmt.Errorf("no curated NVD CPE mapping for %s/%s; skipping NVD to avoid unreliable queries", vendor, product)
	}
	key := "nvd/" + cpe
	return cacheExternalCVEs(key, func() ([]CVEInfo, error) {
		if cves, ok := loadPersistentNVDResult(cpe); ok {
			return cves, nil
		}
		cves, err := queryNVDCPE(cpe)
		if err == nil {
			savePersistentNVDResult(cpe, cves)
		}
		return cves, err
	})
}

func nvdCPEName(vendor, product, version string) string {
	// Use canonical NVD CPE names where fingerprint names differ from NVD.
	switch product {
	case "bootstrap":
		vendor, product = "getbootstrap", "bootstrap"
	case "http_server":
		vendor, product = "apache", "http_server"
	case "jquery":
		vendor, product = "jquery", "jquery"
	case "drupal":
		vendor, product = "drupal", "drupal"
	case "openssl":
		vendor, product = "openssl", "openssl"
	case "nginx":
		vendor, product = "nginx", "nginx"
	case "php":
		vendor, product = "php", "php"
	case "wordpress":
		vendor, product = "wordpress", "wordpress"
	case "mysql":
		vendor, product = "oracle", "mysql"
	case "mariadb":
		vendor, product = "mariadb", "mariadb"
	case "redis":
		vendor, product = "redis", "redis"
	case "elasticsearch":
		vendor, product = "elastic", "elasticsearch"
	case "mongodb":
		vendor, product = "mongodb", "mongodb"
	case "jenkins":
		vendor, product = "jenkins", "jenkins"
	case "grafana":
		vendor, product = "grafana", "grafana"
	case "phpmyadmin":
		vendor, product = "phpmyadmin", "phpmyadmin"
	default:
		// Wappalyzer can return hundreds of labels that are not canonical CPEs.
		// Do not invent CPEs for unrecognized products: these queries are noisy,
		// waste the public NVD request budget, and can create false associations.
		return ""
	}
	if !cpeComponentRE.MatchString(vendor) || !cpeComponentRE.MatchString(product) || !cpeComponentRE.MatchString(version) {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}

type nvdCVEResponse struct {
	Vulnerabilities []struct {
		CVE struct {
			ID             string          `json:"id"`
			Descriptions   json.RawMessage `json:"descriptions"`
			Metrics        json.RawMessage `json:"metrics"`
			References     json.RawMessage `json:"references"`
			Configurations json.RawMessage `json:"configurations"`
		} `json:"cve"`
	} `json:"vulnerabilities"`
}

func queryNVDCPE(cpe string) ([]CVEInfo, error) {
	// Do not queue workers behind a slow/rate-limited NVD request. CIRCL/OSV
	// results remain useful even when NVD enrichment is skipped.
	select {
	case nvdAPISlots <- struct{}{}:
		defer func() { <-nvdAPISlots }()
	default:
		return nil, fmt.Errorf("NVD concurrency guard is busy; skipped this fallback so scanning can continue")
	}

	// This is deliberately non-blocking. When the local request budget is spent
	// or NVD has told us to cool down, skip this fallback instead of stalling all
	// target workers behind a long sleep. CIRCL/OSV results are still retained.
	if err := reserveNVDRequest(); err != nil {
		return nil, err
	}

	query := url.Values{}
	query.Set("cpeName", cpe)
	query.Set("resultsPerPage", "2000")
	req, err := http.NewRequest(http.MethodGet, "https://services.nvd.nist.gov/rest/json/cves/2.0?"+query.Encode(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "SNARE/1.6.6 (+https://github.com/t-onix/snare)")
	if key := strings.TrimSpace(os.Getenv("NVD_API_KEY")); key != "" {
		req.Header.Set("apiKey", key)
	}
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("NVD request: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		cooldown := recordNVDThrottle(resp.StatusCode, resp.Header.Get("Retry-After"), body)
		message := fmt.Sprintf("NVD returned HTTP %d", resp.StatusCode)
		if cooldown > 0 {
			message += fmt.Sprintf("; local NVD cooldown set for %s", cooldown.Round(time.Second))
		}
		if detail := strings.TrimSpace(string(body)); detail != "" {
			message += ": " + compactNVDDetail(detail, 180)
		}
		return nil, fmt.Errorf("%s", message)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxCVEResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxCVEResponseBytes {
		return nil, fmt.Errorf("NVD response exceeded %d bytes", maxCVEResponseBytes)
	}
	var response nvdCVEResponse
	if err := json.Unmarshal(raw, &response); err != nil {
		return nil, fmt.Errorf("decode NVD response: %w", err)
	}
	results := make([]CVEInfo, 0, len(response.Vulnerabilities))
	for _, item := range response.Vulnerabilities {
		cve := item.CVE
		if !strings.HasPrefix(strings.ToUpper(cve.ID), "CVE-") {
			continue
		}
		score := extractCVSS(cve.Metrics)
		refs := uniqueStrings(extractReferences(cve.References))
		results = append(results, CVEInfo{ID: strings.ToUpper(cve.ID), Severity: calculateSeverityFromCVSS(score), CVSS: score, Summary: extractDescription(cve.Descriptions), HasPoC: hasPublicPoCReference(refs), References: refs})
	}
	return results, nil
}

// nvdCacheDirectory honors SNARE_CACHE_DIR for portable deployments and tests;
// otherwise it uses the operating system's standard per-user cache directory.
func nvdCacheDirectory() (string, error) {
	if override := strings.TrimSpace(os.Getenv("SNARE_CACHE_DIR")); override != "" {
		return override, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "snare"), nil
}

func nvdDiskPath(name string) (string, error) {
	dir, err := nvdCacheDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func loadPersistentNVDResult(cpe string) ([]CVEInfo, bool) {
	path, err := nvdDiskPath("nvd-" + nvdCacheKey(cpe) + ".json")
	if err != nil {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var entry nvdDiskEntry
	if json.Unmarshal(raw, &entry) != nil || entry.FetchedAt.IsZero() || time.Since(entry.FetchedAt) > persistentNVDCacheTTL || entry.FetchedAt.After(time.Now().Add(time.Minute)) {
		return nil, false
	}
	return append([]CVEInfo(nil), entry.CVEs...), true
}

func writeCacheFileAtomic(dir, path string, raw []byte) {
	tmp, err := os.CreateTemp(dir, ".snare-cache-*.tmp")
	if err != nil {
		return
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if tmp.Chmod(0600) != nil {
		_ = tmp.Close()
		return
	}
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		return
	}
	if tmp.Sync() != nil || tmp.Close() != nil {
		return
	}
	_ = os.Rename(tmpName, path)
}

func savePersistentNVDResult(cpe string, cves []CVEInfo) {
	path, err := nvdDiskPath("nvd-" + nvdCacheKey(cpe) + ".json")
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	entry := nvdDiskEntry{FetchedAt: time.Now().UTC(), CVEs: append([]CVEInfo(nil), cves...)}
	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	writeCacheFileAtomic(dir, path, raw)
}

func nvdCacheKey(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func nvdRateInterval() time.Duration {
	if strings.TrimSpace(os.Getenv("NVD_API_KEY")) != "" {
		// 40 calls per 30s leaves headroom below the published 50/30s limit.
		return 750 * time.Millisecond
	}
	// Four calls per rolling 30s leaves headroom below the public 5/30s limit.
	return 7500 * time.Millisecond
}

func loadCIRCLThrottleState() {
	circlRateState.Lock()
	defer circlRateState.Unlock()
	loadCIRCLThrottleStateLocked()
}

func loadCIRCLThrottleStateLocked() {
	if circlRateState.loaded {
		return
	}
	circlRateState.loaded = true
	path, err := nvdDiskPath("circl-rate-state.json")
	if err != nil {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var state circlThrottleDiskState
	if json.Unmarshal(raw, &state) == nil {
		circlRateState.cooldownUntil = state.CooldownUntil
	}
}

func circlCooldownRemaining() time.Duration {
	circlRateState.Lock()
	defer circlRateState.Unlock()
	loadCIRCLThrottleStateLocked()
	if time.Until(circlRateState.cooldownUntil) > 0 {
		return time.Until(circlRateState.cooldownUntil)
	}
	return 0
}

func recordCIRCLThrottle(status int, retryAfter string) time.Duration {
	now := time.Now()
	delay := parseRetryAfter(retryAfter, now)
	switch status {
	case http.StatusTooManyRequests:
		if delay <= 0 {
			delay = 30 * time.Second
		}
	case http.StatusServiceUnavailable:
		if delay <= 0 {
			delay = 15 * time.Second
		}
	default:
		return 0
	}
	if delay > 10*time.Minute {
		delay = 10 * time.Minute
	}
	circlRateState.Lock()
	loadCIRCLThrottleStateLocked()
	until := now.Add(delay)
	if until.After(circlRateState.cooldownUntil) {
		circlRateState.cooldownUntil = until
	}
	path, err := nvdDiskPath("circl-rate-state.json")
	if err == nil {
		dir := filepath.Dir(path)
		if os.MkdirAll(dir, 0700) == nil {
			if raw, marshalErr := json.Marshal(circlThrottleDiskState{CooldownUntil: circlRateState.cooldownUntil}); marshalErr == nil {
				writeCacheFileAtomic(dir, path, raw)
			}
		}
	}
	circlRateState.Unlock()
	return delay
}

func loadNVDThrottleState() {
	nvdRateState.Lock()
	defer nvdRateState.Unlock()
	loadNVDThrottleStateLocked()
}

func loadNVDThrottleStateLocked() {
	if nvdRateState.loaded {
		return
	}
	nvdRateState.loaded = true
	path, err := nvdDiskPath("nvd-rate-state.json")
	if err != nil {
		return
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var state nvdThrottleDiskState
	if json.Unmarshal(raw, &state) != nil {
		return
	}
	nvdRateState.nextAllowed = state.NextAllowed
	nvdRateState.cooldownUntil = state.CooldownUntil
}

func persistNVDThrottleStateLocked() {
	path, err := nvdDiskPath("nvd-rate-state.json")
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	state := nvdThrottleDiskState{NextAllowed: nvdRateState.nextAllowed, CooldownUntil: nvdRateState.cooldownUntil}
	raw, err := json.Marshal(state)
	if err != nil {
		return
	}
	writeCacheFileAtomic(dir, path, raw)
}

// reserveNVDRequest reserves a request slot without waiting. A crowded public
// API budget should reduce enrichment completeness, not stop the whole scan.
func reserveNVDRequest() error {
	nvdRateState.Lock()
	defer nvdRateState.Unlock()
	loadNVDThrottleStateLocked()
	now := time.Now()
	if nvdRateState.cooldownUntil.After(now) {
		return fmt.Errorf("NVD cooldown active for %s; skipping this NVD fallback (set NVD_API_KEY for higher throughput)", time.Until(nvdRateState.cooldownUntil).Round(time.Second))
	}
	if nvdRateState.nextAllowed.After(now) {
		return fmt.Errorf("NVD rate guard deferred this lookup for %s; scanning continues without NVD (set NVD_API_KEY for higher throughput)", time.Until(nvdRateState.nextAllowed).Round(time.Second))
	}
	nvdRateState.nextAllowed = now.Add(nvdRateInterval())
	persistNVDThrottleStateLocked()
	return nil
}

func compactNVDDetail(value string, maxRunes int) string {
	value = strings.Join(strings.Fields(value), " ")
	if maxRunes < 1 {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes-1]) + "…"
}

func parseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if when, err := time.Parse(http.TimeFormat, value); err == nil && when.After(now) {
		return when.Sub(now)
	}
	return 0
}

func recordNVDThrottle(status int, retryAfter string, body []byte) time.Duration {
	now := time.Now()
	delay := parseRetryAfter(retryAfter, now)
	switch {
	case status == http.StatusTooManyRequests:
		if delay <= 0 {
			delay = 30 * time.Second
		}
	case status == http.StatusServiceUnavailable:
		// Honor explicit maintenance/backoff instructions from NVD. If absent,
		// use a short cooldown rather than immediately re-hitting a troubled API.
		if delay <= 0 {
			delay = 15 * time.Second
		}
	case status == http.StatusForbidden:
		// NVD may use 403 for a firewall block or rejected API key. Cool down
		// briefly either way to avoid hammering the endpoint while diagnosing it.
		if delay <= 0 {
			delay = time.Minute
		}
	default:
		return 0
	}
	if delay > 10*time.Minute {
		delay = 10 * time.Minute
	}
	nvdRateState.Lock()
	loadNVDThrottleStateLocked()
	until := now.Add(delay)
	if until.After(nvdRateState.cooldownUntil) {
		nvdRateState.cooldownUntil = until
	}
	if nvdRateState.cooldownUntil.After(nvdRateState.nextAllowed) {
		nvdRateState.nextAllowed = nvdRateState.cooldownUntil
	}
	persistNVDThrottleStateLocked()
	nvdRateState.Unlock()
	return delay
}

// resetNVDThrottleForTest clears process state. It is intentionally unexported.
func resetNVDThrottleForTest() {
	nvdRateState.Lock()
	nvdRateState.nextAllowed = time.Time{}
	nvdRateState.cooldownUntil = time.Time{}
	nvdRateState.loaded = false
	nvdRateState.Unlock()
	circlRateState.Lock()
	circlRateState.cooldownUntil = time.Time{}
	circlRateState.loaded = false
	circlRateState.Unlock()
}

type offlineCVERule struct {
	vendor, product string
	minVersion      string
	maxVersion      string
	id, severity    string
	cvss            float64
	summary         string
}

// These records are a small offline fallback, not a replacement for a current
// CVE database. Version ranges follow the cited upstream CVE records. Runtime
// package backports (especially RHEL/CentOS) and config-dependent applicability
// cannot be inferred from a banner, so every fallback result is labelled.
var bundledOfflineRules = []offlineCVERule{
	{"apache", "http_server", "2.4.0", "2.4.27", "CVE-2017-9798", "HIGH", 7.5, "OptionsBleed: memory disclosure in the HTTP OPTIONS method"},
	{"apache", "http_server", "2.4.0", "2.4.25", "CVE-2017-7679", "HIGH", 7.5, "mod_mime buffer over-read vulnerability"},
	{"apache", "http_server", "2.4.0", "2.4.25", "CVE-2017-7668", "HIGH", 7.5, "Apache HTTP Server mod_mime vulnerability"},
	{"apache", "http_server", "2.4.0", "2.4.25", "CVE-2017-7659", "HIGH", 7.5, "HTTP/2 module NULL pointer dereference denial of service"},
	{"apache", "http_server", "2.4.0", "2.4.25", "CVE-2017-3169", "HIGH", 7.5, "mod_ssl NULL pointer dereference vulnerability"},
	{"apache", "http_server", "2.4.0", "2.4.25", "CVE-2017-3167", "HIGH", 7.5, "Apache HTTP Server authentication-related vulnerability"},
	{"apache", "http_server", "2.4.0", "2.4.23", "CVE-2016-8743", "HIGH", 7.5, "Request smuggling, response splitting, and cache pollution in proxy/CGI chains"},
	{"openssl", "openssl", "1.0.1", "1.0.1f", "CVE-2014-0160", "HIGH", 7.5, "Heartbleed: TLS heartbeat memory disclosure"},
	{"openssl", "openssl", "1.0.1", "1.0.1g", "CVE-2014-0224", "HIGH", 7.4, "CCS Injection: TLS ChangeCipherSpec handling may enable a man-in-the-middle attack"},
	{"openssl", "openssl", "1.0.1", "1.0.1g", "CVE-2014-0195", "MEDIUM", 5.8, "DTLS fragment-length validation flaw can cause memory corruption or denial of service"},
	{"openssl", "openssl", "1.0.1", "1.0.1g", "CVE-2014-3470", "HIGH", 7.5, "NULL pointer dereference when an anonymous ECDH cipher suite is used"},
}

func offlineFallbackCVEs(vendor, product, version string) []CVEInfo {
	results := make([]CVEInfo, 0)
	for _, rule := range bundledOfflineRules {
		if !sameCPEPart(rule.vendor, vendor) || !sameCPEPart(rule.product, product) {
			continue
		}
		if rule.minVersion != "" && compareVersions(version, rule.minVersion) < 0 {
			continue
		}
		if rule.maxVersion != "" && compareVersions(version, rule.maxVersion) > 0 {
			continue
		}
		results = append(results, CVEInfo{
			ID:         rule.id,
			Severity:   rule.severity,
			CVSS:       rule.cvss,
			HasPoC:     false, // never infer exploit availability from a CVE title
			Summary:    rule.summary,
			References: []string{"https://nvd.nist.gov/vuln/detail/" + rule.id},
		})
	}
	sort.Slice(results, func(i, j int) bool {
		if results[i].CVSS != results[j].CVSS {
			return results[i].CVSS > results[j].CVSS
		}
		return results[i].ID < results[j].ID
	})
	return results
}

func isRejectedCVERecord(record circlRecord) bool {
	return strings.EqualFold(strings.TrimSpace(record.CVEMetadata.State), "REJECTED")
}

func canonicalCVEID(record circlRecord) string {
	candidates := []string{record.ID, record.CVE, record.CVEID, record.CVEMetadata.CVEID}
	candidates = append(candidates, record.Aliases...)
	for _, candidate := range candidates {
		candidate = strings.ToUpper(strings.TrimSpace(candidate))
		if strings.HasPrefix(candidate, "CVE-") {
			return candidate
		}
	}
	return ""
}

func loadPersistentCIRCLResult(key string) ([]circlRecord, bool) {
	path, err := nvdDiskPath("circl-" + nvdCacheKey(key) + ".json")
	if err != nil {
		return nil, false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var entry circlDiskEntry
	if json.Unmarshal(raw, &entry) != nil || entry.FetchedAt.IsZero() || time.Since(entry.FetchedAt) > persistentCIRCLCacheTTL || entry.FetchedAt.After(time.Now().Add(time.Minute)) {
		return nil, false
	}
	return append([]circlRecord(nil), entry.Records...), true
}

func savePersistentCIRCLResult(key string, records []circlRecord) {
	path, err := nvdDiskPath("circl-" + nvdCacheKey(key) + ".json")
	if err != nil {
		return
	}
	dir := filepath.Dir(path)
	if os.MkdirAll(dir, 0700) != nil {
		return
	}
	raw, err := json.Marshal(circlDiskEntry{FetchedAt: time.Now().UTC(), Records: records})
	if err != nil {
		return
	}
	writeCacheFileAtomic(dir, path, raw)
}

func getProductCVEs(vendor, product string) ([]circlRecord, error) {
	key := strings.ToLower(vendor + "/" + product)
	now := time.Now()

	cveCache.Lock()
	if entry, ok := cveCache.entries[key]; ok && now.Before(entry.expiresAt) {
		records, cachedErr := entry.records, entry.err
		cveCache.Unlock()
		return records, cachedErr
	}
	if call, ok := cveCache.inflight[key]; ok {
		cveCache.Unlock()
		<-call.done
		return call.records, call.err
	}
	call := &cveQueryCall{done: make(chan struct{})}
	cveCache.inflight[key] = call
	cveCache.Unlock()

	records, ok := loadPersistentCIRCLResult(key)
	var err error
	if !ok {
		records, err = queryOnlineAPIs(vendor, product)
		if err == nil {
			savePersistentCIRCLResult(key, records)
		}
	}
	cacheTTL := cveCacheTTL
	if err != nil {
		cacheTTL = cveErrorCacheTTL
	}

	cveCache.Lock()
	call.records = records
	call.err = err
	// Keep the per-process cache bounded during very large target scans.
	now = time.Now()
	if len(cveCache.entries) >= maxCVECacheEntries {
		for cachedKey, entry := range cveCache.entries {
			if !now.Before(entry.expiresAt) {
				delete(cveCache.entries, cachedKey)
			}
		}
	}
	if _, exists := cveCache.entries[key]; exists || len(cveCache.entries) < maxCVECacheEntries {
		cveCache.entries[key] = cveCacheEntry{records: records, err: err, expiresAt: now.Add(cacheTTL)}
	}
	delete(cveCache.inflight, key)
	close(call.done)
	cveCache.Unlock()
	return records, err
}

func queryOnlineAPIs(vendor, product string) ([]circlRecord, error) {
	if !cpeComponentRE.MatchString(vendor) || !cpeComponentRE.MatchString(product) {
		return nil, fmt.Errorf("unsupported CIRCL product mapping %q/%q", vendor, product)
	}
	cveAPISlots <- struct{}{}
	defer func() { <-cveAPISlots }()

	path := "/api/search/" + url.PathEscape(vendor) + "/" + url.PathEscape(product)
	endpoints := []string{
		"https://vulnerability.circl.lu" + path,
		"https://cve.circl.lu" + path,
	}
	var errs []string
	for _, endpoint := range endpoints {
		if remaining := circlCooldownRemaining(); remaining > 0 {
			return nil, fmt.Errorf("CIRCL cooldown active for %s; skipping API requests", remaining.Round(time.Second))
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		records, err := fetchCIRCLRecords(ctx, endpoint)
		cancel()
		if err == nil {
			return records, nil // an empty 200 is a valid no-match, not a reason to query the mirror
		}
		host := endpoint
		if parsed, parseErr := url.Parse(endpoint); parseErr == nil && parsed.Host != "" {
			host = parsed.Host
		}
		errs = append(errs, host+": "+err.Error())
	}
	return nil, fmt.Errorf("all CIRCL endpoints failed: %s", strings.Join(errs, "; "))
}

func fetchCIRCLRecords(ctx context.Context, endpoint string) ([]circlRecord, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "SNARE/1.6.6 (+https://github.com/t-onix/snare)")
	req.Header.Set("Accept", "application/json")
	resp, err := cveHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		errorBody, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		cooldown := recordCIRCLThrottle(resp.StatusCode, resp.Header.Get("Retry-After"))
		message := fmt.Sprintf("HTTP %d", resp.StatusCode)
		if cooldown > 0 {
			message += fmt.Sprintf("; cooldown set for %s", cooldown.Round(time.Second))
		}
		if detail := strings.TrimSpace(string(errorBody)); detail != "" {
			message += ": " + compactNVDDetail(detail, 140)
		}
		return nil, fmt.Errorf("%s", message)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCVEResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxCVEResponseBytes {
		return nil, fmt.Errorf("response exceeded %d bytes", maxCVEResponseBytes)
	}

	// CIRCL's public API has evolved from the legacy top-level array to
	// envelopes whose `results` field can be either an array or an object keyed
	// by CVE ID. Decode collections dynamically rather than binding `results`
	// to []circlRecord: that exact assumption caused the v1.6.5 lookup failure.
	records, recognized, decodeErr := decodeCIRCLRecords(body)
	if decodeErr != nil {
		return nil, fmt.Errorf("decode JSON: %w", decodeErr)
	}
	if !recognized {
		return nil, fmt.Errorf("unrecognized JSON response shape")
	}
	return records, nil
}

// decodeCIRCLRecords accepts both legacy CVE-Search arrays and newer
// Vulnerability-Lookup response envelopes. In the newer shape, `results` may
// be an object containing nested arrays or a map keyed by CVE identifier.
// `recognized` distinguishes a legitimate empty result from an unknown schema.
func decodeCIRCLRecords(body []byte) ([]circlRecord, bool, error) {
	return decodeCIRCLCollection(json.RawMessage(body), 0, "")
}

func decodeCIRCLCollection(raw json.RawMessage, depth int, fallbackID string) ([]circlRecord, bool, error) {
	if depth > 6 {
		return nil, false, fmt.Errorf("CIRCL response nesting exceeds limit")
	}
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
		return nil, false, nil
	}

	switch trimmed[0] {
	case '[':
		var items []json.RawMessage
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, false, err
		}
		records := make([]circlRecord, 0, len(items))
		for _, item := range items {
			// Current Vulnerability-Lookup responses contain CVE List V5 records
			// as ["cve-2025-12345", {"dataType":"CVE_RECORD", ...}] tuples
			// inside results.cvelistv5. The old decoder treated each tuple as a
			// record and silently discarded the entire modern data set.
			if record, ok := decodeCIRCLRecordTuple(item); ok {
				records = append(records, record)
				continue
			}

			record, err := decodeCIRCLRecord(item, "")
			if err == nil && canonicalCVEID(record) != "" {
				records = append(records, record)
				continue
			}

			// Some wrappers nest another collection inside an array element.
			nested, recognized, nestedErr := decodeCIRCLCollection(item, depth+1, fallbackID)
			if nestedErr == nil && recognized && len(nested) > 0 {
				records = append(records, nested...)
			}
		}
		return records, true, nil // an empty array is a valid no-match

	case '{':
		var object map[string]json.RawMessage
		if err := json.Unmarshal(trimmed, &object); err != nil {
			return nil, false, err
		}
		if len(object) == 0 {
			return []circlRecord{}, true, nil // valid empty result object
		}

		// First look for the named result containers used by public API versions.
		for _, key := range []string{"results", "cvelistv5", "data", "vulnerabilities", "items", "records", "vulns", "advisories", "objects", "cves", "entries"} {
			if child, ok := object[key]; ok {
				records, recognized, err := decodeCIRCLCollection(child, depth+1, "")
				if err == nil && recognized {
					return records, true, nil
				}
			}
		}

		// Some responses return a single CVE object rather than a collection.
		if record, err := decodeCIRCLRecord(trimmed, fallbackID); err == nil && canonicalCVEID(record) != "" {
			return []circlRecord{record}, true, nil
		}

		// Newer wrappers can represent results as {"CVE-...": {record}, ...}.
		// Sort keys for deterministic ordering and copy a CVE ID from the key
		// only when the record itself does not carry an identifier.
		keys := make([]string, 0, len(object))
		for key := range object {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		records := make([]circlRecord, 0, len(object))
		for _, key := range keys {
			child := object[key]
			if record, err := decodeCIRCLRecord(child, key); err == nil && canonicalCVEID(record) != "" {
				records = append(records, record)
				continue
			}
			// Also allow another nested envelope level, e.g. {"source": {"results": [...]}}.
			nested, recognized, err := decodeCIRCLCollection(child, depth+1, key)
			if err == nil && recognized {
				records = append(records, nested...)
			}
		}
		if len(records) > 0 {
			return records, true, nil
		}
		return nil, false, nil
	default:
		return nil, false, fmt.Errorf("expected JSON array or object")
	}
}

// decodeCIRCLRecordTuple parses CVE List V5 [identifier, record] pairs used
// by the current CIRCL Vulnerability-Lookup `results.cvelistv5` response.
func decodeCIRCLRecordTuple(raw json.RawMessage) (circlRecord, bool) {
	var tuple []json.RawMessage
	if err := json.Unmarshal(raw, &tuple); err != nil || len(tuple) < 2 {
		return circlRecord{}, false
	}
	var id string
	if err := json.Unmarshal(tuple[0], &id); err != nil {
		return circlRecord{}, false
	}
	id = strings.ToUpper(strings.TrimSpace(id))
	if !strings.HasPrefix(id, "CVE-") {
		return circlRecord{}, false
	}
	record, err := decodeCIRCLRecord(tuple[1], id)
	if err != nil || canonicalCVEID(record) == "" {
		return circlRecord{}, false
	}
	return record, true
}

func decodeCIRCLRecord(raw json.RawMessage, fallbackID string) (circlRecord, error) {
	var record circlRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		return circlRecord{}, err
	}
	if canonicalCVEID(record) == "" && strings.HasPrefix(strings.ToUpper(strings.TrimSpace(fallbackID)), "CVE-") {
		record.ID = strings.ToUpper(strings.TrimSpace(fallbackID))
	}
	return record, nil
}

func recordAffectsVersion(record circlRecord, vendor, product, version string) bool {
	for _, cpe := range record.VulnerableConfiguration {
		if cpeAffectsVersion(cpeConfig{Criteria: cpe}, vendor, product, version) {
			return true
		}
	}
	for _, cpe := range record.VulnerableConfiguration22 {
		if cpeAffectsVersion(cpeConfig{Criteria: cpe}, vendor, product, version) {
			return true
		}
	}
	if rawMatchesVersionConfig(record.VulnerableConfigurationST, vendor, product, version) {
		return true
	}
	if rawMatchesVersionConfig(record.Configurations, vendor, product, version) {
		return true
	}
	if rawAffectedProductMatches(record.Affected, vendor, product, version) || rawAffectedProductMatches(record.CNA, vendor, product, version) || rawAffectedProductMatches(record.Containers, vendor, product, version) {
		return true
	}
	return false
}

func rawMatchesVersionConfig(raw json.RawMessage, vendor, product, version string) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	return walkConfigValue(value, vendor, product, version)
}

func walkConfigValue(value any, vendor, product, version string) bool {
	switch v := value.(type) {
	case string:
		return cpeAffectsVersion(cpeConfig{Criteria: v}, vendor, product, version)
	case []any:
		for _, item := range v {
			if walkConfigValue(item, vendor, product, version) {
				return true
			}
		}
	case map[string]any:
		config := cpeConfig{
			ID:                    stringMapValue(v, "id"),
			Criteria:              stringMapValue(v, "criteria"),
			CPE23URI:              stringMapValue(v, "cpe23Uri"),
			CPE22URI:              stringMapValue(v, "cpe22Uri"),
			VersionStartIncluding: stringMapValue(v, "versionStartIncluding"),
			VersionStartExcluding: stringMapValue(v, "versionStartExcluding"),
			VersionEndIncluding:   stringMapValue(v, "versionEndIncluding"),
			VersionEndExcluding:   stringMapValue(v, "versionEndExcluding"),
		}
		if vulnerable, ok := v["vulnerable"].(bool); ok {
			config.Vulnerable = &vulnerable
		}
		if configHasCPE(config) && cpeAffectsVersion(config, vendor, product, version) {
			return true
		}
		for _, child := range v {
			if walkConfigValue(child, vendor, product, version) {
				return true
			}
		}
	}
	return false
}

func rawAffectedProductMatches(raw json.RawMessage, vendor, product, version string) bool {
	if len(raw) == 0 || string(raw) == "null" {
		return false
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	return walkAffectedValue(value, vendor, product, version)
}

func walkAffectedValue(value any, vendor, product, version string) bool {
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if walkAffectedValue(item, vendor, product, version) {
				return true
			}
		}
	case map[string]any:
		itemVendor := stringMapValue(v, "vendor")
		itemProduct := stringMapValue(v, "product")
		if itemVendor != "" && itemProduct != "" && sameCPEPart(itemVendor, vendor) && sameCPEPart(itemProduct, product) {
			if versions, ok := v["versions"].([]any); ok {
				for _, rawVersion := range versions {
					entry, ok := rawVersion.(map[string]any)
					if !ok {
						continue
					}
					status := strings.ToLower(stringMapValue(entry, "status"))
					if status != "" && status != "affected" {
						continue
					}
					startInc := stringMapValue(entry, "versionStartIncluding")
					startExc := stringMapValue(entry, "versionStartExcluding")
					endInc := stringMapValue(entry, "versionEndIncluding")
					endExc := stringMapValue(entry, "versionEndExcluding")
					lessThan := stringMapValue(entry, "lessThan")
					lessThanOrEqual := stringMapValue(entry, "lessThanOrEqual")
					entryVersion := stringMapValue(entry, "version")

					if entryVersion != "" && entryVersion != "*" && entryVersion != "-" {
						if version == entryVersion {
							return true
						}
						// CVE 5 records frequently describe a half-open interval as
						// version=<lower bound>, lessThan=<upper bound>.
						if lessThan != "" && versionInRange(version, entryVersion, "", "", lessThan) {
							return true
						}
						if lessThanOrEqual != "" && versionInRange(version, entryVersion, "", "", lessThanOrEqual) {
							return true
						}
					}
					if versionInRange(version, startInc, startExc, firstNonEmpty(endInc, lessThanOrEqual), firstNonEmpty(endExc, lessThan)) && (startInc != "" || startExc != "" || endInc != "" || endExc != "" || lessThan != "" || lessThanOrEqual != "") {
						return true
					}
				}
			}
		}
		for _, child := range v {
			if walkAffectedValue(child, vendor, product, version) {
				return true
			}
		}
	}
	return false
}

func cpeAffectsVersion(config cpeConfig, vendor, product, version string) bool {
	if config.Vulnerable != nil && !*config.Vulnerable {
		return false
	}
	cpe := config.Criteria
	if cpe == "" {
		cpe = config.CPE23URI
	}
	if cpe == "" {
		cpe = config.CPE22URI
	}
	if cpe == "" && strings.HasPrefix(strings.ToLower(config.ID), "cpe:") {
		cpe = config.ID
	}
	if cpe == "" {
		return false
	}

	cpeVendor, cpeProduct, cpeVersion, ok := parseCPE(cpe)
	if !ok || !sameCPEPart(cpeVendor, vendor) || !sameCPEPart(cpeProduct, product) {
		return false
	}

	if config.VersionStartIncluding != "" || config.VersionStartExcluding != "" || config.VersionEndIncluding != "" || config.VersionEndExcluding != "" {
		return versionInRange(version, config.VersionStartIncluding, config.VersionStartExcluding, config.VersionEndIncluding, config.VersionEndExcluding)
	}
	// A wildcard CPE is not proof that every version is affected. Require an
	// explicit affected range or exact version to avoid product-wide false positives.
	if cpeVersion == "*" || cpeVersion == "-" || cpeVersion == "" {
		return false
	}
	return cleanVersionString(cpeVersion) == cleanVersionString(version)
}

func configHasCPE(config cpeConfig) bool {
	return config.Criteria != "" || config.CPE23URI != "" || config.CPE22URI != "" || strings.HasPrefix(strings.ToLower(config.ID), "cpe:")
}

func parseCPE(raw string) (vendor, product, version string, ok bool) {
	raw = strings.TrimSpace(strings.Trim(raw, `"`))
	if strings.HasPrefix(strings.ToLower(raw), "cpe:2.3:") {
		parts := strings.Split(raw, ":")
		if len(parts) < 6 {
			return "", "", "", false
		}
		return unescapeCPEPart(parts[3]), unescapeCPEPart(parts[4]), unescapeCPEPart(parts[5]), true
	}
	if strings.HasPrefix(strings.ToLower(raw), "cpe:/") {
		parts := strings.Split(strings.TrimPrefix(raw, "cpe:/"), ":")
		if len(parts) < 4 {
			return "", "", "", false
		}
		return unescapeCPEPart(parts[1]), unescapeCPEPart(parts[2]), unescapeCPEPart(parts[3]), true
	}
	return "", "", "", false
}

func unescapeCPEPart(s string) string {
	s = strings.ReplaceAll(s, `\:`, ":")
	s = strings.ReplaceAll(s, `\_`, "_")
	s = strings.ReplaceAll(s, `\\`, `\`)
	return strings.ToLower(strings.TrimSpace(s))
}

func sameCPEPart(a, b string) bool {
	normalize := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		s = strings.ReplaceAll(s, `\_`, "_")
		s = strings.ReplaceAll(s, " ", "_")
		return s
	}
	return normalize(a) == normalize(b)
}

func versionInRange(version, startIncluding, startExcluding, endIncluding, endExcluding string) bool {
	if version == "" {
		return false
	}
	if startIncluding != "" && compareVersions(version, startIncluding) < 0 {
		return false
	}
	if startExcluding != "" && compareVersions(version, startExcluding) <= 0 {
		return false
	}
	if endIncluding != "" && compareVersions(version, endIncluding) > 0 {
		return false
	}
	if endExcluding != "" && compareVersions(version, endExcluding) >= 0 {
		return false
	}
	return true
}

// compareVersions is a conservative, dependency-free comparator suitable for
// common dotted software versions and simple prerelease suffixes. It is not a
// replacement for every ecosystem's version rules; CPE range metadata still
// depends on the upstream source being accurate.
func compareVersions(a, b string) int {
	a = normalizeVersionForCompare(a)
	b = normalizeVersionForCompare(b)
	if a == b {
		return 0
	}
	aMain, aPre, aHasPre := strings.Cut(a, "-")
	bMain, bPre, bHasPre := strings.Cut(b, "-")
	mainCmp := compareVersionTokens(aMain, bMain)
	if mainCmp != 0 {
		return mainCmp
	}
	if aHasPre != bHasPre {
		if aHasPre {
			return -1
		}
		return 1
	}
	if !aHasPre {
		return 0
	}
	return compareVersionTokens(aPre, bPre)
}

func normalizeVersionForCompare(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	v = strings.TrimPrefix(v, "v")
	if plus := strings.IndexByte(v, '+'); plus >= 0 {
		v = v[:plus]
	}
	return strings.TrimSpace(v)
}

func compareVersionTokens(a, b string) int {
	aTokens := versionTokenRE.FindAllString(strings.ToLower(a), -1)
	bTokens := versionTokenRE.FindAllString(strings.ToLower(b), -1)
	maxLen := len(aTokens)
	if len(bTokens) > maxLen {
		maxLen = len(bTokens)
	}
	for i := 0; i < maxLen; i++ {
		if i >= len(aTokens) {
			if numericToken(bTokens[i]) {
				if trimLeadingZeros(bTokens[i]) == "" {
					continue
				}
				return -1
			}
			return -1
		}
		if i >= len(bTokens) {
			if numericToken(aTokens[i]) {
				if trimLeadingZeros(aTokens[i]) == "" {
					continue
				}
				return 1
			}
			return 1
		}

		x, y := aTokens[i], bTokens[i]
		xNum, yNum := numericToken(x), numericToken(y)
		switch {
		case xNum && yNum:
			x = trimLeadingZeros(x)
			y = trimLeadingZeros(y)
			if len(x) < len(y) {
				return -1
			}
			if len(x) > len(y) {
				return 1
			}
			if x < y {
				return -1
			}
			if x > y {
				return 1
			}
		case xNum && !yNum:
			return 1
		case !xNum && yNum:
			return -1
		default:
			if x < y {
				return -1
			}
			if x > y {
				return 1
			}
		}
	}
	return 0
}

func numericToken(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func trimLeadingZeros(s string) string {
	s = strings.TrimLeft(s, "0")
	return s
}

func cleanVersionString(version string) string {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(strings.TrimPrefix(version, "v"), "V")
	return strings.TrimSpace(version)
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

func normalizeTech(rawName string) (string, string) {
	name := strings.ToLower(strings.TrimSpace(rawName))
	name = strings.Join(strings.Fields(name), " ")
	if name == "" {
		return "", ""
	}

	// These are technology labels/features, not independently versioned
	// software products. Don't send them to the CVE APIs as fabricated CPEs.
	switch name {
	case "basic", "hsts", "http/2", "http/3", "ipv6", "ssl", "tls",
		"jsdelivr", "jquery cdn", "amazon alb", "amazon cloudfront",
		"amazon web services", "cloudfront", "aws", "centos", "red hat",
		"red hat enterprise linux", "rhel":
		return "", ""
	}

	switch {
	case strings.Contains(name, "tomcat"):
		return "apache", "tomcat"
	case name == "mod_ssl", strings.HasPrefix(name, "mod_ssl "),
		name == "apache mod_ssl", name == "apache http server mod_ssl":
		// mod_ssl is an Apache module, not a standalone CVE product. Wappalyzer
		// sometimes reports the Apache version under this module's name.
		return "apache", "http_server"
	case name == "apache", name == "httpd", name == "apache http server", name == "apache httpd", name == "apache http server (httpd)":
		return "apache", "http_server"
	case strings.Contains(name, "apache http server"):
		return "apache", "http_server"
	case name == "nginx", name == "nginx web server":
		return "nginx", "nginx"
	case name == "php", name == "php-fpm", name == "php fpm":
		return "php", "php"
	case name == "openssl" || strings.HasPrefix(name, "openssl "):
		return "openssl", "openssl"
	case name == "wordpress":
		return "wordpress", "wordpress"
	case name == "bootstrap" || strings.HasPrefix(name, "bootstrap ") || name == "twitter bootstrap":
		return "getbootstrap", "bootstrap"
	case name == "drupal":
		return "drupal", "drupal"
	case name == "jquery" || strings.HasPrefix(name, "jquery "):
		return "jquery", "jquery"
	case strings.Contains(name, "internet information services"), name == "iis", strings.Contains(name, "microsoft iis"):
		return "microsoft", "internet_information_server"
	case name == "node.js", name == "nodejs":
		return "nodejs", "node.js"
	case name == "phpmyadmin":
		return "phpmyadmin", "phpmyadmin"
	case name == "mysql", name == "mariadb", name == "postgresql", name == "redis", name == "elasticsearch", name == "mongodb":
		return name, name
	case name == "jenkins":
		return "jenkins", "jenkins"
	case name == "grafana":
		return "grafana", "grafana"
	case name == "django":
		return "djangoproject", "django"
	case name == "flask":
		return "palletsprojects", "flask"
	case name == "laravel":
		return "laravel", "framework"
	case name == "apache struts", name == "struts":
		return "apache", "struts"
	}

	// Wappalyzer contains hundreds of product names, so don't fail closed for
	// every technology we have not curated yet. Use a conservative CPE-ish slug
	// as a best-effort NVD/CIRCL candidate, but never allow characters that
	// could alter a URL path or a CPE component. If it cannot be represented,
	// report PRODUCT UNMAPPED rather than LOOKUP UNAVAILABLE.
	clean := strings.NewReplacer(" ", "_", "/", "_", "\\", "_", ":", "_", "?", "", "#", "").Replace(name)
	clean = strings.Trim(clean, "_.-")
	if clean == "" || !cpeComponentRE.MatchString(clean) {
		return "", ""
	}
	return clean, clean
}

func parseTechVersion(raw string) TechMatch {
	if strings.Contains(raw, ":") {
		parts := strings.SplitN(raw, ":", 2)
		return TechMatch{
			Name:    strings.TrimSpace(parts[0]),
			Version: cleanVersionString(strings.TrimSpace(parts[1])),
		}
	}
	return TechMatch{Name: strings.TrimSpace(raw)}
}

func stringMapValue(values map[string]any, key string) string {
	if value, ok := values[key].(string); ok {
		return value
	}
	return ""
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func extractReferences(raws ...json.RawMessage) []string {
	var references []string
	for index, raw := range raws {
		if len(raw) == 0 {
			continue
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			continue
		}
		walk := func(any, bool) {}
		walk = func(value any, insideReferences bool) {
			switch v := value.(type) {
			case string:
				if insideReferences && (strings.HasPrefix(strings.ToLower(v), "https://") || strings.HasPrefix(strings.ToLower(v), "http://")) {
					references = append(references, v)
				}
			case []any:
				for _, child := range v {
					walk(child, insideReferences)
				}
			case map[string]any:
				for key, child := range v {
					walk(child, insideReferences || strings.EqualFold(key, "references"))
				}
			}
		}
		// The legacy API places references at the root; newer CVE records nest
		// them under containers.cna.references.
		walk(value, index == 0)
	}
	return references
}

func uniqueStrings(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func hasPublicPoCReference(references []string) bool {
	for _, reference := range references {
		ref := strings.ToLower(reference)
		if strings.Contains(ref, "exploit-db.com") ||
			strings.Contains(ref, "packetstormsecurity.com") ||
			strings.Contains(ref, "metasploit.com") ||
			strings.Contains(ref, "github.com") && (strings.Contains(ref, "exploit") || strings.Contains(ref, "poc") || strings.Contains(ref, "proof-of-concept")) {
			return true
		}
	}
	return false
}

func extractCVSS(raw json.RawMessage) float64 {
	if len(raw) == 0 {
		return 0
	}
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return 0
	}
	best := 0.0
	var visit func(any)
	visit = func(item any) {
		switch v := item.(type) {
		case float64:
			if v > best && v <= 10 {
				best = v
			}
		case []any:
			for _, child := range v {
				visit(child)
			}
		case map[string]any:
			if score, ok := v["baseScore"].(float64); ok && score > best && score <= 10 {
				best = score
			}
			for _, child := range v {
				visit(child)
			}
		}
	}
	visit(value)
	return best
}

func extractDescription(raws ...json.RawMessage) string {
	for _, raw := range raws {
		if len(raw) == 0 {
			continue
		}
		var value any
		if json.Unmarshal(raw, &value) != nil {
			continue
		}
		if description := findEnglishDescription(value); description != "" {
			return description
		}
	}
	return "Description unavailable in vulnerability source"
}

func findEnglishDescription(value any) string {
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			if result := findEnglishDescription(item); result != "" {
				return result
			}
		}
	case map[string]any:
		lang := strings.ToLower(stringMapValue(v, "lang"))
		text := stringMapValue(v, "value")
		if text == "" {
			text = stringMapValue(v, "description")
		}
		if text != "" && (lang == "" || lang == "en" || strings.HasPrefix(lang, "en-")) {
			return strings.TrimSpace(text)
		}
		for _, child := range v {
			if result := findEnglishDescription(child); result != "" {
				return result
			}
		}
	}
	return ""
}
