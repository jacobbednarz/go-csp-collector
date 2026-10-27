package handler

import (
	"bytes"
	"encoding/json"
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

func sampleNELReport(url string) []NELReport {
	return []NELReport{
		{
			Age:       100,
			Type:      "network-error",
			URL:       url,
			UserAgent: "Mozilla/5.0",
			Body: NELReportBody{
				ElapsedTime:      42,
				Method:           "GET",
				Phase:            "connection",
				Protocol:         "h2",
				Referrer:         "https://example.com/",
				SamplingFraction: 1.0,
				ServerIP:         "93.184.216.34",
				StatusCode:       0,
				Type:             "tcp.refused",
			},
		},
	}
}

func TestGenericNELHandlerDisallowedMethods(t *testing.T) {
	l, _ := newTestLogger()
	h := NewNELHandler(false, Options{Logger: l, Metrics: newTestMetrics()})

	for _, method := range []string{"GET", "PUT", "DELETE", "PATCH", "TRACE"} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/nel", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405, got %d", rr.Code)
			}
		})
	}
}

func TestGenericNELHandlerInvalidJSON(t *testing.T) {
	l, _ := newTestLogger()
	h := NewNELHandler(false, Options{Logger: l, Metrics: newTestMetrics()})

	req := httptest.NewRequest("POST", "/nel", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", rr.Code)
	}
}

func TestGenericNELHandlerSkipsInvalidURLAndKeepsRestOfBatch(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, logBuf := newTestLogger()
	h := NewNELHandler(false, Options{Logger: l, Metrics: m})

	payload, _ := json.Marshal(append(sampleNELReport("about:blank"), sampleNELReport("https://example.com/nel-good")...))
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("nel", "validation_error")); got != 1 {
		t.Errorf("reports_errors_total validation_error = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.NELReports.WithLabelValues("enforced")); got != 1 {
		t.Errorf("nel_reports_total enforced = %v, want 1", got)
	}
	out := logBuf.String()
	if !strings.Contains(out, "nel-good") || strings.Contains(out, "about:blank") {
		t.Errorf("expected only the valid report logged, got: %s", out)
	}
}

func TestGenericNELHandlerLogsReportOnly(t *testing.T) {
	l, logBuf := newTestLogger()
	h := NewNELHandler(true, Options{Logger: l, Metrics: newTestMetrics()})

	payload, _ := json.Marshal(sampleNELReport("https://example.com/page"))
	req := httptest.NewRequest("POST", "/nel/report-only", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(logBuf.String(), "report_only=true") {
		t.Errorf("expected report_only=true in log output, got: %s", logBuf.String())
	}
}

func TestGenericNELHandlerSkipsNonNetworkErrorReports(t *testing.T) {
	l, logBuf := newTestLogger()
	h := NewNELHandler(false, Options{Logger: l, Metrics: newTestMetrics()})

	reports := []NELReport{
		{Type: "csp-violation", URL: "https://example.com/"},
	}
	payload, _ := json.Marshal(reports)
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if strings.Contains(logBuf.String(), "url=") {
		t.Errorf("expected no log output for non-network-error report, got: %s", logBuf.String())
	}
}

func TestGenericNELHandlerMixedBatchPreservesWellFormedReport(t *testing.T) {
	l, logBuf := newTestLoggerAtLevel(slog.LevelDebug)
	h := NewNELHandler(false, Options{Logger: l, Metrics: newTestMetrics()})

	payload := []byte(`[
		{"age":0,"type":"network-error","url":"https://example.com/nel-good","user_agent":"t","body":{"status_code":200,"type":"ok"}},
		{"age":0,"type":"network-error","url":"https://example.com/nel-bad","user_agent":"t","body":{"status_code":"not-a-number","type":"ok"}}
	]`)

	req := httptest.NewRequest("POST", "/nel", bytes.NewReader(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	out := logBuf.String()
	if !strings.Contains(out, "nel-good") {
		t.Errorf("expected well-formed report to still be logged, got: %s", out)
	}
	if !strings.Contains(out, "item_decode_error") {
		t.Errorf("expected malformed item to be logged with a fallback reason, got: %s", out)
	}
}

func TestGenericNELHandlerMetricsSuccessAndIgnored(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()

	h := NewNELHandler(false, Options{Logger: l, Metrics: m})
	reports := []NELReport{
		{Type: "network-error", URL: "https://example.com/ok", Body: NELReportBody{Type: "tcp.refused", Phase: "connection"}},
		{Type: "csp-violation", URL: "https://example.com/skip"},
	}

	payload, _ := json.Marshal(reports)
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// NEL counts in reports_total like every other handler, and in the
	// deprecated nel_reports_total until it's removed.
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("nel", "enforced")); got != 1 {
		t.Fatalf("reports_total nel enforced = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.NELReports.WithLabelValues("enforced")); got != 1 {
		t.Fatalf("nel_reports_total enforced = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ReportIgnored.WithLabelValues("nel", "unsupported_type")); got != 1 {
		t.Fatalf("reports_ignored_total = %v, want 1", got)
	}
}

func TestGenericNELHandlerRejectsBareObject(t *testing.T) {
	// NEL never sets SingleObject, so unlike /csp, a valid but
	// non-array body must still be rejected, not silently accepted as a
	// single-item batch.
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := NewNELHandler(false, Options{Logger: l, Metrics: m})

	payload, _ := json.Marshal(sampleNELReport("https://example.com/page")[0])
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for a bare object, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("nel", "decode_error")); got != 1 {
		t.Fatalf("reports_errors_total decode_error = %v, want 1", got)
	}
}

func TestGenericNELHandlerTruncatesQueryStringFragment(t *testing.T) {
	l, rec := newRecordingLogger(slog.LevelInfo)
	h := NewNELHandler(false, Options{TruncateQueryStringFragment: true, Logger: l, Metrics: newTestMetrics()})

	reports := []NELReport{
		{
			Type: "network-error",
			URL:  "https://example.com/page?a=b#frag",
			Body: NELReportBody{Type: "tcp.refused", Referrer: "https://ref.example.com/?a=b#frag"},
		},
	}
	payload, _ := json.Marshal(reports)
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	got := urlFields(t, rec, "url", "referrer")
	want := Fields{"url": "https://example.com/page", "referrer": "https://ref.example.com/"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("truncated fields = %v, want %v", got, want)
	}
}
