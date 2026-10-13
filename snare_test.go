package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestParseCPE23(t *testing.T) {
	vendor, product, version, ok := parseCPE("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*")
	if !ok || vendor != "apache" || product != "http_server" || version != "2.4.49" {
		t.Fatalf("unexpected parse: %q %q %q %v", vendor, product, version, ok)
	}
}

func TestParseCPE22(t *testing.T) {
	vendor, product, version, ok := parseCPE("cpe:/a:apache:http_server:2.4.49")
	if !ok || vendor != "apache" || product != "http_server" || version != "2.4.49" {
		t.Fatalf("unexpected parse: %q %q %q %v", vendor, product, version, ok)
	}
}

func TestCPEExactVersionRequiresExactMatch(t *testing.T) {
	config := cpeConfig{Criteria: "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"}
	if !cpeAffectsVersion(config, "apache", "http_server", "2.4.49") {
		t.Fatal("expected exact CPE version to match")
	}
	if cpeAffectsVersion(config, "apache", "http_server", "2.4.48") {
		t.Fatal("exact CPE version must not match a different version")
	}
}

func TestWildcardCPEWithoutRangeIsNotConfirmed(t *testing.T) {
	config := cpeConfig{Criteria: "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"}
	if cpeAffectsVersion(config, "apache", "http_server", "2.4.49") {
		t.Fatal("wildcard without range must not become a product-wide false positive")
	}
}

func TestDecodeCIRCLResultsObjectKeyedByCVEID(t *testing.T) {
	payload := []byte(`{
	  "total": 2,
	  "results": {
	    "CVE-2025-12345": {
	      "id": "CVE-2025-12345",
	      "cvss": 7.5,
	      "summary": "Legacy-shaped object record",
	      "vulnerable_configuration": ["cpe:2.3:a:apache:http_server:2.2.31:*:*:*:*:*:*:*"]
	    },
	    "CVE-2025-12346": {
	      "cveMetadata": {"cveId": "CVE-2025-12346"},
	      "cvss": {"baseScore": 9.8},
	      "containers": {"cna": {"descriptions": [{"lang":"en", "value":"Modern CVE record"}]}}
	    }
	  }
	}`)

	records, recognized, err := decodeCIRCLRecords(payload)
	if err != nil {
		t.Fatalf("decodeCIRCLRecords() error: %v", err)
	}
	if !recognized {
		t.Fatal("object-based results envelope must be recognized")
	}
	if len(records) != 2 {
		t.Fatalf("expected 2 records from keyed object; got %d: %#v", len(records), records)
	}
	ids := map[string]bool{}
	for _, record := range records {
		ids[canonicalCVEID(record)] = true
	}
	if !ids["CVE-2025-12345"] || !ids["CVE-2025-12346"] {
		t.Fatalf("unexpected CVE IDs parsed from object response: %#v", ids)
	}
	for _, record := range records {
		if canonicalCVEID(record) == "CVE-2025-12345" && extractCVSS(record.CVSS) != 7.5 {
			t.Fatalf("numeric CVSS was not parsed: got %v", extractCVSS(record.CVSS))
		}
		if canonicalCVEID(record) == "CVE-2025-12346" && extractCVSS(record.CVSS) != 9.8 {
			t.Fatalf("object CVSS was not parsed: got %v", extractCVSS(record.CVSS))
		}
	}
}

func TestDecodeCIRCLNestedResultsAndLegacyArray(t *testing.T) {
	for name, payload := range map[string]string{
		"nested object":         `{"results":{"data":[{"cveMetadata":{"cveId":"CVE-2025-22222"},"summary":"Nested result"}]},"count":1}`,
		"legacy array":          `[{"id":"CVE-2025-33333","summary":"Legacy array result"}]`,
		"empty object":          `{"results":{}}`,
		"empty cvelistv5 array": `{"results":{"cvelistv5":[]}}`,
	} {
		t.Run(name, func(t *testing.T) {
			records, recognized, err := decodeCIRCLRecords([]byte(payload))
			if err != nil || !recognized {
				t.Fatalf("response was not accepted: recognized=%v err=%v", recognized, err)
			}
			if name == "empty object" || name == "empty cvelistv5 array" {
				if len(records) != 0 {
					t.Fatalf("expected valid empty result, got %#v", records)
				}
				return
			}
			if len(records) != 1 || canonicalCVEID(records[0]) == "" {
				t.Fatalf("expected one parsed CVE record, got %#v", records)
			}
		})
	}
}

func TestDecodeCIRCLCurrentCVEListV5TupleShape(t *testing.T) {
	// This mirrors CIRCL's current public API envelope:
	// results -> cvelistv5 -> [[lowercase CVE ID, CVE_RECORD object], ...].
	payload := []byte(`{
	  "results": {
	    "cvelistv5": [
	      ["cve-2099-12345", {
	        "dataType": "CVE_RECORD",
	        "dataVersion": "5.1",
	        "cveMetadata": {"cveId": "CVE-2099-12345", "state": "PUBLISHED"},
	        "containers": {"cna": {
	          "affected": [{
	            "vendor": "getbootstrap",
	            "product": "bootstrap",
	            "versions": [{"version": "4.0.0", "lessThan": "6.0.0", "status": "affected", "versionType": "semver"}]
	          }],
	          "descriptions": [{"lang": "en", "value": "CVE List V5 tuple format fixture"}],
	          "metrics": [{"cvssV3_1": {"baseScore": 7.5}}],
	          "references": [{"url": "https://example.invalid/advisory"}]
	        }}
	      }]
	    ]
	  }
	}`)

	records, recognized, err := decodeCIRCLRecords(payload)
	if err != nil || !recognized {
		t.Fatalf("CVE List V5 payload not recognized: recognized=%v err=%v", recognized, err)
	}
	if len(records) != 1 {
		t.Fatalf("expected one tuple record, got %d: %#v", len(records), records)
	}
	record := records[0]
	if got := canonicalCVEID(record); got != "CVE-2099-12345" {
		t.Fatalf("CVE ID = %q, want CVE-2099-12345", got)
	}
	if !recordAffectsVersion(record, "getbootstrap", "bootstrap", "5.0.2") {
		t.Fatal("expected product/version range in CVE List V5 record to match Bootstrap 5.0.2")
	}
	if got := extractDescription(record.Descriptions, record.CNA, record.Containers); got != "CVE List V5 tuple format fixture" {
		t.Fatalf("description = %q", got)
	}
	if got := extractCVSS(record.Containers); got != 7.5 {
		t.Fatalf("CVSS = %v, want 7.5", got)
	}
	refs := extractReferences(record.References, record.Containers, record.CNA)
	if len(refs) != 1 || refs[0] != "https://example.invalid/advisory" {
		t.Fatalf("references parsed incorrectly: %#v", refs)
	}
}

func TestCIRCLRejectedRecordIsIdentified(t *testing.T) {
	payload := []byte(`{"results":{"cvelistv5":[["cve-2099-11111",{"cveMetadata":{"cveId":"CVE-2099-11111","state":"REJECTED"}}]]}}`)
	records, recognized, err := decodeCIRCLRecords(payload)
	if err != nil || !recognized || len(records) != 1 {
		t.Fatalf("rejected record failed to decode: recognized=%v records=%d err=%v", recognized, len(records), err)
	}
	if !isRejectedCVERecord(records[0]) {
		t.Fatal("record state REJECTED should be recognized to prevent rescinded CVEs from being reported")
	}
}

func TestDecodeCIRCLCurrentTupleCanUseTupleIDFallback(t *testing.T) {
	payload := []byte(`{"results":{"cvelistv5":[["cve-2099-98765", {"dataType":"CVE_RECORD", "containers":{"cna":{"descriptions":[{"lang":"en","value":"no metadata id"}]}}}]]}}`)
	records, recognized, err := decodeCIRCLRecords(payload)
	if err != nil || !recognized || len(records) != 1 {
		t.Fatalf("tuple with fallback ID not decoded: recognized=%v records=%d err=%v", recognized, len(records), err)
	}
	if got := canonicalCVEID(records[0]); got != "CVE-2099-98765" {
		t.Fatalf("fallback CVE ID = %q", got)
	}
}

func TestCPEVersionRange(t *testing.T) {
	config := cpeConfig{
		Criteria:              "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
		VersionStartIncluding: "2.4.50",
		VersionEndExcluding:   "2.4.55",
	}
	for _, tc := range []struct {
		version string
		want    bool
	}{
		{"2.4.49", false},
		{"2.4.50", true},
		{"2.4.53", true},
		{"2.4.55", false},
	} {
		t.Run(tc.version, func(t *testing.T) {
			if got := cpeAffectsVersion(config, "apache", "http_server", tc.version); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRecordAffectsExactVersion(t *testing.T) {
	record := circlRecord{
		ID: "CVE-2021-41773",
		VulnerableConfiguration: []string{
			"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		},
	}
	if !recordAffectsVersion(record, "apache", "http_server", "2.4.49") {
		t.Fatal("expected vulnerability to match affected version")
	}
	if recordAffectsVersion(record, "apache", "http_server", "2.4.51") {
		t.Fatal("unexpected match for a different exact version")
	}
}

func TestRecordAffectsCVE5Range(t *testing.T) {
	record := circlRecord{Containers: json.RawMessage(`{
	  "cna": {"affected": [{
	    "vendor": "apache", "product": "http_server",
	    "versions": [{"version":"2.4.49", "lessThan":"2.4.51", "status":"affected"}]
	  }]}
	}`)}
	if !recordAffectsVersion(record, "apache", "http_server", "2.4.50") {
		t.Fatal("expected target inside CVE 5 range to match")
	}
	if recordAffectsVersion(record, "apache", "http_server", "2.4.51") {
		t.Fatal("expected exclusive upper bound not to match")
	}
}

func TestVersionComparator(t *testing.T) {
	for _, tc := range []struct {
		a, b string
		want int
	}{
		{"2.4.9", "2.4.10", -1},
		{"2.4.10", "2.4.9", 1},
		{"1.2.0", "1.2", 0},
		{"1.0.0-rc1", "1.0.0", -1},
		{"1.0.1f", "1.0.1", 1},
	} {
		t.Run(tc.a+"_vs_"+tc.b, func(t *testing.T) {
			got := compareVersions(tc.a, tc.b)
			if (got < 0 && tc.want >= 0) || (got > 0 && tc.want <= 0) || (got == 0 && tc.want != 0) {
				t.Fatalf("compareVersions(%q, %q) = %d; wanted sign %d", tc.a, tc.b, got, tc.want)
			}
		})
	}
}

func TestNormalizeCommonTech(t *testing.T) {
	for _, tc := range []struct{ name, vendor, product string }{
		{"Apache HTTP Server", "apache", "http_server"},
		{"Nginx", "nginx", "nginx"},
		{"OpenSSL", "openssl", "openssl"},
		{"mod_ssl", "apache", "http_server"},
		{"Apache mod_ssl", "apache", "http_server"},
	} {
		vendor, product := normalizeTech(tc.name)
		if vendor != tc.vendor || product != tc.product {
			t.Errorf("normalizeTech(%q) = %q/%q; want %q/%q", tc.name, vendor, product, tc.vendor, tc.product)
		}
	}
}

func TestNormalizeNonProductLabelsDoesNotInventCPE(t *testing.T) {
	for _, label := range []string{"HSTS", "Basic", "Amazon CloudFront", "jsDelivr"} {
		if vendor, product := normalizeTech(label); vendor != "" || product != "" {
			t.Errorf("normalizeTech(%q) = %q/%q, expected no product mapping", label, vendor, product)
		}
	}
}

func TestCanonicalCVEIDUsesAlias(t *testing.T) {
	record := circlRecord{ID: "GHSA-abcd-efgh-ijkl", Aliases: []string{"GHSA-abcd-efgh-ijkl", "CVE-2025-12345"}}
	if got := canonicalCVEID(record); got != "CVE-2025-12345" {
		t.Fatalf("canonicalCVEID() = %q", got)
	}
}

func TestExtractReferencesSupportsLegacyAndCVE5Formats(t *testing.T) {
	legacy := json.RawMessage(`[
	  "https://nvd.nist.gov/vuln/detail/CVE-2025-12345",
	  "https://www.exploit-db.com/exploits/12345"
	]`)
	modern := json.RawMessage(`{"containers":{"cna":{"references":[{"url":"https://example.test/advisory"}]}}}`)
	got := uniqueStrings(extractReferences(legacy, modern))
	if len(got) != 3 {
		t.Fatalf("expected 3 references, got %#v", got)
	}
}

func TestNormalizeAvoidsConfusingApacheTomcatAndPHPMyAdmin(t *testing.T) {
	if vendor, product := normalizeTech("Apache Tomcat"); vendor != "apache" || product != "tomcat" {
		t.Fatalf("Apache Tomcat mapped to %q/%q", vendor, product)
	}
	if vendor, product := normalizeTech("phpMyAdmin"); vendor == "php" && product == "php" {
		t.Fatalf("phpMyAdmin must not be mistaken for the PHP runtime")
	}
}

func TestNonVulnerableCPEConfigIsIgnored(t *testing.T) {
	vulnerable := false
	config := cpeConfig{
		Criteria:   "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
		Vulnerable: &vulnerable,
	}
	if cpeAffectsVersion(config, "apache", "http_server", "2.4.49") {
		t.Fatal("a non-vulnerable CPE match must not be reported")
	}
}

func TestOfflineFallbackMatchesApache246(t *testing.T) {
	found := offlineFallbackCVEs("apache", "http_server", "2.4.6")
	if len(found) < 5 {
		t.Fatalf("expected bundled Apache 2.4.6 fallback CVEs, got %d", len(found))
	}
	for _, cve := range found {
		if !strings.HasPrefix(cve.ID, "CVE-") || len(cve.References) == 0 {
			t.Fatalf("invalid fallback CVE record: %#v", cve)
		}
	}
}

func TestOfflineFallbackMatchesOpenSSL101e(t *testing.T) {
	found := offlineFallbackCVEs("openssl", "openssl", "1.0.1e")
	if len(found) < 3 {
		t.Fatalf("expected bundled OpenSSL 1.0.1e fallback CVEs, got %d", len(found))
	}
	for _, cve := range found {
		if cve.ID == "CVE-2014-0160" {
			return
		}
	}
	t.Fatal("Heartbleed must match OpenSSL 1.0.1e")
}

func TestOfflineFallbackDoesNotMatchFixedApacheVersion(t *testing.T) {
	for _, cve := range offlineFallbackCVEs("apache", "http_server", "2.4.58") {
		if cve.ID == "CVE-2017-9798" || cve.ID == "CVE-2017-7679" {
			t.Fatalf("unexpected old Apache fallback for 2.4.58: %s", cve.ID)
		}
	}
}

func TestQueueUniqueTargetDeduplicatesCaseAndTrailingSlash(t *testing.T) {
	seen := make(map[string]struct{})
	out := make(chan string, 4)
	queueUniqueTarget("http://example.test/", out, seen)
	queueUniqueTarget("HTTP://EXAMPLE.TEST", out, seen)
	queueUniqueTarget("https://example.test", out, seen)
	close(out)
	count := 0
	for range out {
		count++
	}
	if count != 2 {
		t.Fatalf("expected exact duplicate to be removed while preserving other schemes, got %d targets", count)
	}
}

type testRoundTripper func(*http.Request) (*http.Response, error)

func (fn testRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }

func TestOSVVersionRangeMatchesOnlyAffectedVersions(t *testing.T) {
	var vuln osvVulnerability
	payload := `{"id":"GHSA-test","aliases":["CVE-2025-12345"],"affected":[{"package":{"name":"bootstrap","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"5.2.2"}]}]}]}`
	if err := json.Unmarshal([]byte(payload), &vuln); err != nil {
		t.Fatal(err)
	}
	if !osvAffectsPackageVersion(vuln, "bootstrap", "npm", "5.1.1") {
		t.Fatal("Bootstrap 5.1.1 should fall inside the affected range")
	}
	if osvAffectsPackageVersion(vuln, "bootstrap", "npm", "5.2.2") {
		t.Fatal("the fixed version must not be included in the affected range")
	}
	if osvAffectsPackageVersion(vuln, "jquery", "npm", "5.1.1") {
		t.Fatal("a different package must not match this advisory")
	}
	if got := preferredOSVIdentifier(vuln); got != "CVE-2025-12345" {
		t.Fatalf("preferredOSVIdentifier() = %q", got)
	}
}

func TestOSVPackageMappings(t *testing.T) {
	for _, tc := range []struct{ product, name, ecosystem string }{
		{"bootstrap", "bootstrap", "npm"},
		{"jquery", "jquery", "npm"},
		{"drupal", "drupal/core", "Packagist"},
	} {
		name, ecosystem, ok := osvPackageFor("", tc.product)
		if !ok || name != tc.name || ecosystem != tc.ecosystem {
			t.Errorf("osvPackageFor(%q) = %q/%q/%v", tc.product, name, ecosystem, ok)
		}
	}
	if _, _, ok := osvPackageFor("", "unknown-product"); ok {
		t.Fatal("unknown products must not be mapped to an invented OSV package")
	}
}

func TestNVDUsesCanonicalCPENames(t *testing.T) {
	for _, tc := range []struct{ vendor, product, version, want string }{
		{"getbootstrap", "bootstrap", "5.1.1", "cpe:2.3:a:getbootstrap:bootstrap:5.1.1:*:*:*:*:*:*:*"},
		{"drupal", "drupal", "10", "cpe:2.3:a:drupal:drupal:10:*:*:*:*:*:*:*"},
		{"jquery", "jquery", "3.6.0", "cpe:2.3:a:jquery:jquery:3.6.0:*:*:*:*:*:*:*"},
	} {
		if got := nvdCPEName(tc.vendor, tc.product, tc.version); got != tc.want {
			t.Errorf("nvdCPEName(%q/%q@%q) = %q, want %q", tc.vendor, tc.product, tc.version, got, tc.want)
		}
	}
	if got := nvdCPEName("x", "x", "10/../../bad"); got != "" {
		t.Fatalf("unsafe version should be rejected, got CPE %q", got)
	}
	if got := nvdCPEName("unknown", "autogenerated_technology", "1.2.3"); got != "" {
		t.Fatalf("unrecognized products must not invent CPEs, got %q", got)
	}
}

func setupNVDTestState(t *testing.T) {
	t.Helper()
	t.Setenv("SNARE_CACHE_DIR", t.TempDir())
	t.Setenv("NVD_API_KEY", "fixture-key")
	resetNVDThrottleForTest()
}

func TestNVDResponseParserAndCVSS(t *testing.T) {
	setupNVDTestState(t)
	originalClient := cveHTTPClient
	defer func() { cveHTTPClient = originalClient }()
	cveHTTPClient = &http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
		if !strings.Contains(req.URL.RawQuery, "cpeName=") {
			t.Errorf("request missing CPE query: %s", req.URL)
		}
		body := `{"vulnerabilities":[{"cve":{"id":"CVE-2025-12345","descriptions":[{"lang":"en","value":"Fixture vulnerability"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":9.8}}]},"references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-12345"}]}}]}`
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
	})}
	got, err := queryNVDCPE("cpe:2.3:a:jquery:jquery:3.6.0:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one CVE, got %#v", got)
	}
	if got[0].ID != "CVE-2025-12345" || got[0].CVSS != 9.8 || got[0].Severity != "CRITICAL" || got[0].Summary != "Fixture vulnerability" {
		t.Fatalf("NVD response not normalized correctly: %#v", got[0])
	}
}

func TestLookupFallsBackToOSVWhenCIRCLIsUnavailable(t *testing.T) {
	originalClient := cveHTTPClient
	defer func() { cveHTTPClient = originalClient }()
	var nvdCalls int
	cveHTTPClient = &http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "vulnerability.circl.lu", "cve.circl.lu":
			return nil, errors.New("simulated CIRCL outage")
		case "api.osv.dev":
			body := `{"vulns":[{"id":"GHSA-example","aliases":["CVE-2025-12345"],"summary":"Fixture Bootstrap advisory","references":[{"url":"https://example.test/advisory"}],"affected":[{"package":{"name":"bootstrap","ecosystem":"npm"},"ranges":[{"type":"SEMVER","events":[{"introduced":"0"},{"fixed":"5.2.2"}]}]}]}]}`
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		case "services.nvd.nist.gov":
			nvdCalls++
			return nil, errors.New("NVD should not be needed when OSV already found a CVE")
		default:
			return nil, errors.New("unexpected endpoint: " + req.URL.Host)
		}
	})}

	cves, status, diagnostic := lookupVulnerabilitiesDetailed("Bootstrap", "5.1.1")
	if len(cves) != 1 || cves[0].ID != "CVE-2025-12345" {
		t.Fatalf("expected version-matched OSV CVE, got %#v", cves)
	}
	if status != "matched_partial" {
		t.Fatalf("status = %q, want matched_partial (CIRCL failed)", status)
	}
	if diagnostic == "" {
		t.Fatal("expected the CIRCL failure to remain visible as a diagnostic")
	}
	if nvdCalls != 0 {
		t.Fatalf("NVD should not be queried after OSV returned an applicable finding; got %d calls", nvdCalls)
	}
}

func TestLookupUsesNVDWhenCIRCLFailsAndVersionIsMajorOnly(t *testing.T) {
	setupNVDTestState(t)
	originalClient := cveHTTPClient
	defer func() { cveHTTPClient = originalClient }()
	cveHTTPClient = &http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "vulnerability.circl.lu", "cve.circl.lu":
			return nil, errors.New("simulated CIRCL outage")
		case "services.nvd.nist.gov":
			body := `{"vulnerabilities":[{"cve":{"id":"CVE-2025-54321","descriptions":[{"lang":"en","value":"Fixture Drupal vulnerability"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":8.1}}]},"references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-54321"}]}}]}`
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		default:
			return nil, errors.New("unexpected endpoint: " + req.URL.Host)
		}
	})}

	cves, status, diagnostic := lookupVulnerabilitiesDetailed("Drupal", "10")
	if len(cves) != 1 || cves[0].ID != "CVE-2025-54321" {
		t.Fatalf("expected NVD fallback CVE, got %#v", cves)
	}
	if status != "matched_partial" || diagnostic == "" {
		t.Fatalf("status=%q diagnostic=%q, want matched_partial with source diagnostic", status, diagnostic)
	}
}

func TestLookupUsesNVDWhenOSVHasNoMatches(t *testing.T) {
	setupNVDTestState(t)
	originalClient := cveHTTPClient
	defer func() { cveHTTPClient = originalClient }()
	var nvdCalls int
	cveHTTPClient = &http.Client{Transport: testRoundTripper(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host {
		case "vulnerability.circl.lu", "cve.circl.lu":
			return nil, errors.New("simulated CIRCL outage")
		case "api.osv.dev":
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"vulns":[]}`)), Request: req}, nil
		case "services.nvd.nist.gov":
			nvdCalls++
			body := `{"vulnerabilities":[{"cve":{"id":"CVE-2025-98765","descriptions":[{"lang":"en","value":"Fixture advisory returned by NVD fallback"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":7.5}}]},"references":[{"url":"https://nvd.nist.gov/vuln/detail/CVE-2025-98765"}]}}]}`
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(body)), Request: req}, nil
		default:
			return nil, errors.New("unexpected endpoint: " + req.URL.Host)
		}
	})}

	// Unique version avoids any prior test's version-keyed external cache.
	cves, status, diagnostic := lookupVulnerabilitiesDetailed("Bootstrap", "5.987.654")
	if len(cves) != 1 || cves[0].ID != "CVE-2025-98765" {
		t.Fatalf("expected NVD fallback after empty OSV results, got %#v", cves)
	}
	if nvdCalls != 1 {
		t.Fatalf("expected one NVD call after empty OSV results, got %d", nvdCalls)
	}
	if status != "matched_partial" || diagnostic == "" {
		t.Fatalf("status=%q diagnostic=%q, want matched_partial plus CIRCL diagnostic", status, diagnostic)
	}
}

func TestPersistentCIRCLCacheSurvivesRestart(t *testing.T) {
	t.Setenv("SNARE_CACHE_DIR", t.TempDir())
	key := "apache/http_server"
	want := []circlRecord{{ID: "CVE-2026-12345", Summary: "fixture record"}}
	savePersistentCIRCLResult(key, want)
	got, ok := loadPersistentCIRCLResult(key)
	if !ok || len(got) != 1 || got[0].ID != want[0].ID {
		t.Fatalf("persistent CIRCL cache miss or corruption: ok=%v got=%#v", ok, got)
	}
}

func TestCIRCL429PersistsCooldown(t *testing.T) {
	t.Setenv("SNARE_CACHE_DIR", t.TempDir())
	resetNVDThrottleForTest()
	delay := recordCIRCLThrottle(http.StatusTooManyRequests, "10")
	if delay != 10*time.Second {
		t.Fatalf("cooldown=%s, want 10s", delay)
	}
	resetNVDThrottleForTest()
	if remaining := circlCooldownRemaining(); remaining <= 0 {
		t.Fatalf("expected CIRCL cooldown to persist after restart, got %s", remaining)
	}
}

func TestNVDRateGuardIsNonBlockingAndPersistsAcrossRestart(t *testing.T) {
	t.Setenv("SNARE_CACHE_DIR", t.TempDir())
	t.Setenv("NVD_API_KEY", "")
	resetNVDThrottleForTest()
	if err := reserveNVDRequest(); err != nil {
		t.Fatalf("first NVD request should be permitted: %v", err)
	}
	start := time.Now()
	err := reserveNVDRequest()
	if err == nil || !strings.Contains(err.Error(), "rate guard deferred") {
		t.Fatalf("second request should be deferred by the rate guard, got %v", err)
	}
	if time.Since(start) > 100*time.Millisecond {
		t.Fatalf("rate guard blocked instead of returning immediately: %s", time.Since(start))
	}

	// Simulate Ctrl+C/restart: memory clears, persisted state still prevents a burst.
	resetNVDThrottleForTest()
	err = reserveNVDRequest()
	if err == nil || !strings.Contains(err.Error(), "rate guard deferred") {
		t.Fatalf("persisted pacing state should survive restart, got %v", err)
	}
}

func TestNVD429PersistsRetryAfterCooldown(t *testing.T) {
	t.Setenv("SNARE_CACHE_DIR", t.TempDir())
	resetNVDThrottleForTest()
	delay := recordNVDThrottle(http.StatusTooManyRequests, "12", []byte("rate limited"))
	if delay != 12*time.Second {
		t.Fatalf("cooldown=%s, want 12s", delay)
	}
	resetNVDThrottleForTest()
	err := reserveNVDRequest()
	if err == nil || !strings.Contains(err.Error(), "cooldown active") {
		t.Fatalf("expected persisted cooldown after restart, got %v", err)
	}
}

func TestWrapANSIContainsLongWordsAndDescriptions(t *testing.T) {
	const width = 34
	input := ColorPeach + "[PARTIAL LOOKUP]" + ColorReset + " " +
		strings.Repeat("https://provider.example/api/very-long-unbroken-path/", 4) + " " +
		strings.Repeat("long vulnerability description ", 8) + "🔥"
	lines := wrapANSI(input, width)
	if len(lines) < 3 {
		t.Fatalf("expected wrapping of long contents, got %d lines", len(lines))
	}
	for i, line := range lines {
		if got := visibleLength(line); got > width {
			t.Errorf("wrapped line %d has visible width %d > %d: %q", i, got, width, line)
		}
	}
	if !strings.Contains(strings.Join(lines, "\n"), "[PARTIAL LOOKUP]") {
		t.Fatal("wrapping dropped visible warning text")
	}
}

func TestRenderTargetCardKeepsLongRowsInsideBorders(t *testing.T) {
	previousStdout := os.Stdout
	readPipe, writePipe, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	previousJSONMode := isJSONMode
	setJSONMode(false)
	os.Stdout = writePipe

	renderTargetCard("https://example.test/"+strings.Repeat("very-long-path-segment/", 12), []TechResult{{
		Tech:      TechMatch{Name: "Apache HTTP Server", Version: "2.4.6"},
		CVEStatus: "matched_partial",
		CVEError:  strings.Repeat("provider.example/path/", 30),
		CVEs: []CVEInfo{{
			ID: "CVE-2025-12345", Severity: "HIGH", CVSS: 7.5,
			Summary: strings.Repeat("unbroken-summary-token", 12) + " affects a long description",
		}},
	}})
	_ = writePipe.Close()
	os.Stdout = previousStdout
	setJSONMode(previousJSONMode)
	defer readPipe.Close()

	output, err := io.ReadAll(readPipe)
	if err != nil {
		t.Fatal(err)
	}
	for i, line := range strings.Split(string(output), "\n") {
		if got := visibleLength(line); got > 115 {
			t.Errorf("rendered output line %d exceeds box width: %d cells", i+1, got)
		}
	}
}
