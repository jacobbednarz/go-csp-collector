package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
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
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := NewNELHandler(false, false, false, false, false, l, nil)

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
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := NewNELHandler(false, false, false, false, false, l, nil)

	req := httptest.NewRequest("POST", "/nel", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", rr.Code)
	}
}

func TestGenericNELHandlerInvalidURLReturns400(t *testing.T) {
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := NewNELHandler(false, false, false, false, false, l, nil)

	payload, _ := json.Marshal(sampleNELReport("about:blank"))
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestGenericNELHandlerLogsReportOnly(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)
	h := NewNELHandler(true, false, false, false, false, l, nil)

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
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)
	h := NewNELHandler(false, false, false, false, false, l, nil)

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
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)
	h := NewNELHandler(false, false, false, false, false, l, nil)

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
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewNELHandler(false, false, false, false, false, l, m)
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
	if got := testutil.ToFloat64(m.NELReports.WithLabelValues("enforced")); got != 1 {
		t.Fatalf("nel_reports_total enforced = %v, want 1 (RecordSuccessMetric should preserve the legacy metric name)", got)
	}
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("nel", "enforced")); got != 0 {
		t.Fatalf("reports_total nel enforced = %v, want 0 (NEL should not double-record onto the shared metric)", got)
	}
	if got := testutil.ToFloat64(m.ReportIgnored.WithLabelValues("nel", "unsupported_type")); got != 1 {
		t.Fatalf("reports_ignored_total = %v, want 1", got)
	}
}
