package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
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

func newTestCSPHandler(blockedURIs, blockedDomains []string, l *slog.Logger, m *metrics.Metrics) http.Handler {
	return NewCSPHandler(false, Filter{BlockedURIs: blockedURIs, BlockedDomains: blockedDomains}, Options{Logger: l, Metrics: m})
}

func TestCSPReportType(t *testing.T) {
	t.Parallel()

	if got := (CSPReport{}).ReportType(); got != "csp-violation" {
		t.Errorf("expected ReportType() to return %q, got %q", "csp-violation", got)
	}
}

func TestGenericCSPHandlerInvalidBlockedURIs(t *testing.T) {
	t.Parallel()

	for _, blockedURI := range invalidBlockedURIs {
		// Makes the test name more readable for the output.
		testName := strings.ReplaceAll(blockedURI, "://", "")

		t.Run(testName, func(t *testing.T) {
			t.Parallel()

			rawReport := []byte(fmt.Sprintf(`{
				"csp-report": {
					"document-uri": "https://example.com",
					"blocked-uri": "%s"
				}
			}`, blockedURI))

			l, _ := newTestLogger()
			h := newTestCSPHandler(invalidBlockedURIs, nil, l, newTestMetrics())

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
	t.Parallel()

	rawReport := []byte(`{
		"csp-report": {
			"document-uri": "https://example.com",
			"blocked-uri": "https://google.com/example.css"
		}
	}`)

	l, _ := newTestLogger()
	h := newTestCSPHandler(invalidBlockedURIs, nil, l, newTestMetrics())

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(rawReport))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGenericCSPHandlerNonHttpDocumentURI(t *testing.T) {
	t.Parallel()

	rawReport := []byte(`{
		"csp-report": {
			"document-uri": "about",
			"blocked-uri": "http://example.com/"
		}
	}`)

	l, _ := newTestLogger()
	h := newTestCSPHandler(invalidBlockedURIs, nil, l, newTestMetrics())

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
	t.Parallel()

	csp := CSPReport{
		CSPReportBody{
			DocumentURI: "http://example.com",
			BlockedURI:  "http://example.com",
		},
	}

	payload, _ := json.Marshal(csp)

	for _, repeats := range []int{1, 2} {
		l, logBuffer := newTestLogger()

		url := "/?"
		for i := 0; i < repeats; i++ {
			url += fmt.Sprintf("metadata=value%d&", i)
		}

		request, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
		if err != nil {
			t.Fatalf("failed to create request: %v", err)
		}
		recorder := httptest.NewRecorder()

		h := newTestCSPHandler(invalidBlockedURIs, nil, l, newTestMetrics())
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
	t.Parallel()

	csp := CSPReport{
		CSPReportBody{
			DocumentURI: "http://example.com",
			BlockedURI:  "http://example.com",
		},
	}

	payload, _ := json.Marshal(csp)

	l, logBuffer := newTestLogger()

	request, err := http.NewRequest("POST", "/path?a=b&c=d", bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	recorder := httptest.NewRecorder()

	h := NewCSPHandler(false, Filter{}, Options{MetadataObject: true, Logger: l, Metrics: newTestMetrics()})
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
	t.Parallel()

	statusCodeValues := []any{"200", 200}

	for _, statusCode := range statusCodeValues {
		t.Run(fmt.Sprintf("%T", statusCode), func(t *testing.T) {
			t.Parallel()

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
			l, _ := newTestLogger()
			h := newTestCSPHandler(invalidBlockedURIs, nil, l, newTestMetrics())
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
	t.Parallel()

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

	l, _ := newTestLogger()
	h := newTestCSPHandler(invalidBlockedURIs, nil, l, newTestMetrics())

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(rawReport))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Unexpected error raised: %d %s", rr.Code, rr.Body.String())
	}
}

func TestIsBlockedByDomain(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			got := isBlockedByDomain(tc.blockedURI, domains)
			if got != tc.want {
				t.Errorf("isBlockedByDomain(%q) = %v, want %v", tc.blockedURI, got, tc.want)
			}
		})
	}
}

func TestIsBlockedByDomainEmptyList(t *testing.T) {
	t.Parallel()

	if isBlockedByDomain("https://example.com/foo", []string{}) {
		t.Error("expected false for empty domain list")
	}
	if isBlockedByDomain("https://example.com/foo", nil) {
		t.Error("expected false for nil domain list")
	}
}

func TestGenericCSPHandlerBlockedDomain(t *testing.T) {
	t.Parallel()

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
			t.Parallel()

			rawReport := fmt.Sprintf(`{
				"csp-report": {
					"document-uri": "https://example.com",
					"blocked-uri": "%s"
				}
			}`, tc.blockedURI)

			l, _ := newTestLogger()
			h := newTestCSPHandler(nil, blockedDomains, l, newTestMetrics())

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
	t.Parallel()

	payload := []byte(`{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://cdn.example.com/app.js"}}`)
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()

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
	t.Parallel()

	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()

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
	t.Parallel()

	payload := []byte(`{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://ads.example-tracker.com/asset.js"}}`)
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()

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

func TestCSPHandlerMetricsFilteredURI(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"csp-report":{"document-uri":"https://example.com","blocked-uri":"inline"}}`)
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()

	h := newTestCSPHandler([]string{"inline"}, nil, l, m)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportFiltered.WithLabelValues("csp", "blocked_uri")); got != 1 {
		t.Fatalf("reports_filtered_total blocked_uri = %v, want 1", got)
	}
}

func TestCSPHandlerMetricsValidationError(t *testing.T) {
	t.Parallel()

	payload := []byte(`{"csp-report":{"document-uri":"about:blank","blocked-uri":"https://cdn.example.com/app.js"}}`)
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()

	h := newTestCSPHandler(nil, nil, l, m)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("csp", "validation_error")); got != 1 {
		t.Fatalf("reports_errors_total validation_error = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ReportFiltered.WithLabelValues("csp", "validation_error")); got != 0 {
		t.Fatalf("reports_filtered_total validation_error = %v, want 0", got)
	}
}

func TestGenericCSPHandlerReportOnly(t *testing.T) {
	t.Parallel()

	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, logBuffer := newTestLogger()

	h := NewCSPHandler(true, Filter{}, Options{Logger: l, Metrics: m})

	payload := []byte(`{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://cdn.example.com/app.js"}}`)
	req := httptest.NewRequest("POST", "/csp/report-only", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(logBuffer.String(), "report_only=true") {
		t.Errorf("expected report_only=true in log output, got: %s", logBuffer.String())
	}
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("csp", "report_only")); got != 1 {
		t.Fatalf("reports_total report_only = %v, want 1", got)
	}
}

// CSP3 adds `disposition` to the report body. The browser knows which
// header the policy came from, so it wins over the route; browsers that
// omit it fall back to the route the report was sent to.
func TestCSPHandlerReportOnlyFromDisposition(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		routeReportOnly bool
		disposition     string
		wantReportOnly  bool
		wantMode        string
	}{
		{name: "enforce_route_no_disposition", routeReportOnly: false, disposition: "", wantReportOnly: false, wantMode: "enforced"},
		{name: "report_only_route_no_disposition", routeReportOnly: true, disposition: "", wantReportOnly: true, wantMode: "report_only"},
		{name: "enforce_route_report_disposition", routeReportOnly: false, disposition: "report", wantReportOnly: true, wantMode: "report_only"},
		{name: "report_only_route_enforce_disposition", routeReportOnly: true, disposition: "enforce", wantReportOnly: false, wantMode: "enforced"},
		{name: "matching_route_and_disposition", routeReportOnly: true, disposition: "report", wantReportOnly: true, wantMode: "report_only"},
		{name: "unknown_disposition_uses_route", routeReportOnly: true, disposition: "bogus", wantReportOnly: true, wantMode: "report_only"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := prometheus.NewRegistry()
			m := metrics.New(registry)
			l, rec := newRecordingLogger(slog.LevelInfo)
			h := NewCSPHandler(tt.routeReportOnly, Filter{}, Options{Logger: l, Metrics: m})

			payload := fmt.Sprintf(`{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://cdn.example.com/app.js","disposition":%q}}`, tt.disposition)
			req := httptest.NewRequest("POST", "/csp", strings.NewReader(payload))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
			entries := rec.Entries()
			if len(entries) != 1 {
				t.Fatalf("got %d log entries, want 1", len(entries))
			}
			if got := entries[0].Data["report_only"]; got != tt.wantReportOnly {
				t.Errorf("report_only = %v, want %v", got, tt.wantReportOnly)
			}
			if got := testutil.CollectAndCount(m.Reports); got != 1 {
				t.Fatalf("reports_total has %d series, want 1", got)
			}
			if got := testutil.ToFloat64(m.Reports.WithLabelValues("csp", tt.wantMode)); got != 1 {
				t.Errorf("reports_total %s = %v, want 1", tt.wantMode, got)
			}
		})
	}
}

func TestGenericCSPHandlerTruncatesQueryStringFragment(t *testing.T) {
	t.Parallel()

	l, rec := newRecordingLogger(slog.LevelInfo)

	h := NewCSPHandler(false, Filter{}, Options{TruncateQueryStringFragment: true, Logger: l, Metrics: newTestMetrics()})

	payload := []byte(`{"csp-report":{"document-uri":"https://example.com/?a=b#frag","referrer":"https://ref.example.com/?a=b#frag","blocked-uri":"https://cdn.example.com/app.js?a=b#frag","source-file":"https://example.com/app.js?a=b#frag"}}`)
	req := httptest.NewRequest("POST", "/csp", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	got := urlFields(t, rec, "document_uri", "referrer", "blocked_uri", "source_file")
	want := Fields{
		"document_uri": "https://example.com/",
		"referrer":     "https://ref.example.com/",
		"blocked_uri":  "https://cdn.example.com/app.js",
		"source_file":  "https://example.com/app.js",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("truncated fields = %v, want %v", got, want)
	}
}

// The CSP spec has report-uri deliver exactly one un-batched object, so
// anything else must fail the whole request the same way the original
// single-struct decoder did, never be partially accepted.
func TestCSPHandlerRejectsBodiesThatAreNotASingleReport(t *testing.T) {
	t.Parallel()

	report := `{"csp-report":{"document-uri":"https://example.com","blocked-uri":"https://cdn.example.com/one.js"}}`
	tests := []struct {
		name       string
		body       string
		wantStatus int
		wantReason string
	}{
		{name: "array_of_reports", body: "[" + report + "," + report + "]", wantStatus: http.StatusUnprocessableEntity, wantReason: "decode_error"},
		{name: "empty_array", body: "[]", wantStatus: http.StatusUnprocessableEntity, wantReason: "decode_error"},
		{name: "number", body: "123", wantStatus: http.StatusUnprocessableEntity, wantReason: "decode_error"},
		{name: "string", body: `"report"`, wantStatus: http.StatusUnprocessableEntity, wantReason: "decode_error"},
		{name: "mistyped_field", body: `{"csp-report":{"document-uri":"https://example.com","line-number":"abc"}}`, wantStatus: http.StatusUnprocessableEntity, wantReason: "decode_error"},
		{name: "null", body: "null", wantStatus: http.StatusBadRequest, wantReason: "validation_error"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			registry := prometheus.NewRegistry()
			m := metrics.New(registry)
			l, _ := newTestLogger()
			h := newTestCSPHandler(nil, nil, l, m)

			req := httptest.NewRequest("POST", "/csp", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantStatus {
				t.Fatalf("expected %d, got %d: %s", tt.wantStatus, rr.Code, rr.Body.String())
			}
			if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("csp", tt.wantReason)); got != 1 {
				t.Errorf("reports_errors_total %s = %v, want 1", tt.wantReason, got)
			}
			if got := testutil.CollectAndCount(m.Reports); got != 0 {
				t.Errorf("reports_total has %d series, want 0", got)
			}
		})
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
