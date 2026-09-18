package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

var blockedDomains = []string{
	"kaspersky-labs.com",
	"example-tracker.com",
	"ads.example.net",
}

var invalidBlockedURIs = []string{
	"resource://",
	"chromenull://",
	"chrome-extension://",
	"safari-extension://",
	"mxjscall://",
	"webviewprogressproxy://",
	"res://",
	"mx://",
	"safari-resource://",
	"chromeinvoke://",
	"chromeinvokeimmediate://",
	"mbinit://",
	"opera://",
	"localhost",
	"127.0.0.1",
	"none://",
	"about:blank",
	"android-webview",
	"ms-browser-extension",
	"wvjbscheme://__wvjb_queue_message__",
	"nativebaiduhd://adblock",
	"bdvideo://error",
}

func newTestCSPHandler(blockedURIs, blockedDomains []string, l *logrus.Logger, m *metrics.Metrics) http.Handler {
	return NewCSPHandler(false, blockedURIs, blockedDomains, false, false, false, false, l, m)
}

func TestGenericCSPHandlerInvalidBlockedURIs(t *testing.T) {
	for _, blockedURI := range invalidBlockedURIs {
		// Makes the test name more readable for the output.
		testName := strings.ReplaceAll(blockedURI, "://", "")

		t.Run(testName, func(t *testing.T) {
			rawReport := []byte(fmt.Sprintf(`{
				"csp-report": {
					"document-uri": "https://example.com",
					"blocked-uri": "%s"
				}
			}`, blockedURI))

			l := logrus.New()
			l.SetOutput(bytes.NewBuffer(nil))
			h := newTestCSPHandler(invalidBlockedURIs, nil, l, nil)

			req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(rawReport))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d", rr.Code)
			}

			wantBody := fmt.Sprintf("blocked URI ('%s') is an invalid resource", blockedURI)
			if strings.TrimSpace(rr.Body.String()) != wantBody {
				t.Errorf("expected body %q, got %q", wantBody, rr.Body.String())
			}
		})
	}
}

func TestGenericCSPHandlerValidBlockedURIs(t *testing.T) {
	rawReport := []byte(`{
		"csp-report": {
			"document-uri": "https://example.com",
			"blocked-uri": "https://google.com/example.css"
		}
	}`)

	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := newTestCSPHandler(invalidBlockedURIs, nil, l, nil)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(rawReport))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGenericCSPHandlerNonHttpDocumentURI(t *testing.T) {
	rawReport := []byte(`{
		"csp-report": {
			"document-uri": "about",
			"blocked-uri": "http://example.com/"
		}
	}`)

	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := newTestCSPHandler(invalidBlockedURIs, nil, l, nil)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(rawReport))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if want := "document URI ('about') is invalid"; strings.TrimSpace(rr.Body.String()) != want {
		t.Errorf("expected body %q, got %q", want, rr.Body.String())
	}
}

func TestGenericCSPHandlerWithMetadata(t *testing.T) {
	csp := CSPReport{
		CSPReportBody{
			DocumentURI: "http://example.com",
			BlockedURI:  "http://example.com",
		},
	}

	payload, _ := json.Marshal(csp)

	for _, repeats := range []int{1, 2} {
		l := logrus.New()
		var logBuffer bytes.Buffer
		l.SetOutput(&logBuffer)

		url := "/?"
		for i := 0; i < repeats; i++ {
			url += fmt.Sprintf("metadata=value%d&", i)
		}

		request, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		recorder := httptest.NewRecorder()

		h := newTestCSPHandler(invalidBlockedURIs, nil, l, nil)
		h.ServeHTTP(recorder, request)

		response := recorder.Result()
		defer response.Body.Close()

		if response.StatusCode != http.StatusOK {
			t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
		}

		logOut := logBuffer.String()
		if !strings.Contains(logOut, "metadata=value0") {
			t.Fatalf("Logged result should contain metadata value0 in '%s'", logOut)
		}
		if strings.Contains(logOut, "metadata=value1") {
			t.Fatalf("Logged result shouldn't contain metadata value1 in '%s'", logOut)
		}
	}
}

func TestGenericCSPHandlerWithMetadataObject(t *testing.T) {
	csp := CSPReport{
		CSPReportBody{
			DocumentURI: "http://example.com",
			BlockedURI:  "http://example.com",
		},
	}

	payload, _ := json.Marshal(csp)

	l := logrus.New()
	var logBuffer bytes.Buffer
	l.SetOutput(&logBuffer)

	request, err := http.NewRequest("POST", "/path?a=b&c=d", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	recorder := httptest.NewRecorder()

	h := NewCSPHandler(false, nil, nil, false, false, false, true, l, nil)
	h.ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
	}

	logOut := logBuffer.String()
	if !strings.Contains(logOut, "metadata=\"map[a:b c:d]\"") {
		t.Fatalf("Logged result should contain metadata map '%s'", logOut)
	}
}

func TestGenericCSPHandlerMultipleTypeStatusCode(t *testing.T) {
	statusCodeValues := []interface{}{"200", 200}

	for _, statusCode := range statusCodeValues {
		t.Run(fmt.Sprintf("%T", statusCode), func(t *testing.T) {
			csp := CSPReport{
				CSPReportBody{
					DocumentURI: "https://example.com",
					StatusCode:  statusCode,
				},
			}

			payload, err := json.Marshal(csp)
			if err != nil {
				t.Fatalf("failed to marshal JSON: %v", err)
			}

			request, err := http.NewRequest("POST", "/", bytes.NewBuffer(payload))
			if err != nil {
				t.Fatalf("failed to create request: %v", err)
			}

			recorder := httptest.NewRecorder()
			l := logrus.New()
			l.SetOutput(bytes.NewBuffer(nil))
			h := newTestCSPHandler(invalidBlockedURIs, nil, l, nil)
			h.ServeHTTP(recorder, request)

			response := recorder.Result()
			defer response.Body.Close()

			if response.StatusCode != http.StatusOK {
				t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
			}
		})
	}
}

func TestGenericCSPHandlerWithSourceFile(t *testing.T) {
	rawReport := []byte(`{
		"csp-report": {
			"document-uri": "https://example.com",
			"blocked-uri": "https://google.com/example.css",
			"column-number": 70774,
			"line-number": 2,
			"source-file": "https://example.com/example.js"
		}
	}`)

	var report CSPReport
	if err := json.Unmarshal(rawReport, &report); err != nil {
		t.Fatalf("error: %s", err)
	}
	if report.Body.SourceFile == "" {
		t.Errorf("Violation 'source-file' not found")
	}
	if report.Body.LineNumber == 0 {
		t.Errorf("Violation 'line-number' not found")
	}
	if report.Body.ColumnNumber == 0 {
		t.Errorf("Violation 'column-number' not found")
	}

	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := newTestCSPHandler(invalidBlockedURIs, nil, l, nil)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(rawReport))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Unexpected error raised: %d %s", rr.Code, rr.Body.String())
	}
}

func TestIsBlockedByDomain(t *testing.T) {
	domains := []string{"kaspersky-labs.com", "example-tracker.com"}

	cases := []struct {
		blockedURI string
		want       bool
	}{
		// Exact domain match.
		{"https://kaspersky-labs.com/script.js", true},
		// Single subdomain.
		{"https://gc.kis.v2.scr.kaspersky-labs.com/foo", true},
		// Deeply nested subdomain.
		{"https://a.b.c.kaspersky-labs.com/bar", true},
		// Different domain entirely — must not block.
		{"https://example.com/script.js", false},
		// Domain that only shares a suffix but is not a subdomain — must not block.
		{"https://evilkaspersky-labs.com/x", false},
		// Non-URL blocked-uri values common in CSP reports — must not block.
		{"about:blank", false},
		{"resource://", false},
		{"chrome-extension://abc", false},
		// Empty domain list edge case handled separately in TestIsBlockedByDomainEmptyList.
	}

	for _, tc := range cases {
		t.Run(tc.blockedURI, func(t *testing.T) {
			got := isBlockedByDomain(tc.blockedURI, domains)
			if got != tc.want {
				t.Errorf("isBlockedByDomain(%q) = %v, want %v", tc.blockedURI, got, tc.want)
			}
		})
	}
}

func TestIsBlockedByDomainEmptyList(t *testing.T) {
	if isBlockedByDomain("https://example.com/foo", []string{}) {
		t.Error("expected false for empty domain list")
	}
	if isBlockedByDomain("https://example.com/foo", nil) {
		t.Error("expected false for nil domain list")
	}
}

func TestGenericCSPHandlerBlockedDomain(t *testing.T) {
	cases := []struct {
		name       string
		blockedURI string
		wantStatus int
	}{
		{
			name:       "exact domain is blocked",
			blockedURI: "https://kaspersky-labs.com/script.js",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "subdomain is blocked",
			blockedURI: "https://gc.kis.v2.scr.kaspersky-labs.com/foo",
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unrelated domain is allowed",
			blockedURI: "https://legitimate.example.com/style.css",
			wantStatus: http.StatusOK,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rawReport := fmt.Sprintf(`{
				"csp-report": {
					"document-uri": "https://example.com",
					"blocked-uri": "%s"
				}
			}`, tc.blockedURI)

			l := logrus.New()
			l.SetOutput(bytes.NewBuffer(nil))
			h := newTestCSPHandler(nil, blockedDomains, l, nil)

			req := httptest.NewRequest("POST", "/csp", bytes.NewBufferString(rawReport))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tc.wantStatus {
				t.Errorf("expected status %d, got %d: %s", tc.wantStatus, rr.Code, rr.Body.String())
			}
		})
	}
}

func TestCSPHandlerMetricsSuccess(t *testing.T) {
	payload := []byte(`{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://cdn.example.com/app.js"}}`)
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := newTestCSPHandler(nil, nil, l, m)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("csp", "enforced")); got != 1 {
		t.Fatalf("reports_total = %v, want 1", got)
	}
}

func TestCSPHandlerMetricsDecodeError(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := newTestCSPHandler(nil, nil, l, m)

	req := httptest.NewRequest("POST", "/csp", strings.NewReader("bad-json"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("csp", "decode_error")); got != 1 {
		t.Fatalf("reports_errors_total decode_error = %v, want 1", got)
	}
}

func TestCSPHandlerMetricsFilteredDomain(t *testing.T) {
	payload := []byte(`{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://ads.example-tracker.com/asset.js"}}`)
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := newTestCSPHandler(nil, []string{"example-tracker.com"}, l, m)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportFiltered.WithLabelValues("csp", "blocked_domain")); got != 1 {
		t.Fatalf("reports_filtered_total blocked_domain = %v, want 1", got)
	}
}

// TestGenericCSPHandlerAcceptsArrayOfReports documents a deliberate behavior
// change from the original single-object-only CSPViolationReportHandler:
// AllowSingleObject only changes what happens when the body ISN'T an array,
// it doesn't stop the handler from accepting one. A genuine JSON array of
// several csp-report objects now succeeds and processes each entry,
// something the old decoder (`Decode(&report)` into a single struct) would
// have rejected outright as a decode error.
func TestGenericCSPHandlerAcceptsArrayOfReports(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := newTestCSPHandler(nil, nil, l, m)

	payload := []byte(`[
		{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://cdn.example.com/one.js"}},
		{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://cdn.example.com/two.js"}}
	]`)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("csp", "enforced")); got != 2 {
		t.Fatalf("reports_total = %v, want 2", got)
	}
}

// The benchmarks below compare the two filter implementations under equivalent
// conditions: a 5-entry list where the matching entry is last (worst-case scan)
// and a no-match case (full scan).

// BenchmarkBlockedURIsMatch measures prefix filtering when the URI matches the
// last entry in the list.
func BenchmarkBlockedURIsMatch(b *testing.B) {
	prefixes := []string{
		"resource://",
		"chrome-extension://",
		"safari-extension://",
		"localhost",
		"about:blank",
	}
	uri := "about:blank"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range prefixes {
			if strings.HasPrefix(uri, p) {
				break
			}
		}
	}
}

// BenchmarkBlockedURIsNoMatch measures prefix filtering when nothing in the
// list matches, forcing a full scan.
func BenchmarkBlockedURIsNoMatch(b *testing.B) {
	prefixes := []string{
		"resource://",
		"chrome-extension://",
		"safari-extension://",
		"localhost",
		"about:blank",
	}
	uri := "https://legitimate.example.com/some/path"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, p := range prefixes {
			if strings.HasPrefix(uri, p) {
				break
			}
		}
	}
}

// BenchmarkBlockedDomainsMatch measures domain filtering when the hostname
// matches the last entry in the list.
func BenchmarkBlockedDomainsMatch(b *testing.B) {
	domains := []string{
		"google-analytics.com",
		"facebook.net",
		"doubleclick.net",
		"ads.twitter.com",
		"kaspersky-labs.com",
	}
	uri := "https://gc.kis.v2.scr.kaspersky-labs.com/some/path"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isBlockedByDomain(uri, domains)
	}
}

// BenchmarkBlockedDomainsNoMatch measures domain filtering when nothing in
// the list matches, forcing a full scan.
func BenchmarkBlockedDomainsNoMatch(b *testing.B) {
	domains := []string{
		"google-analytics.com",
		"facebook.net",
		"doubleclick.net",
		"ads.twitter.com",
		"kaspersky-labs.com",
	}
	uri := "https://legitimate.example.com/some/path"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		isBlockedByDomain(uri, domains)
	}
}
