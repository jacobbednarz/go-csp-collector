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

func TestGenericReportAPICSPHandlerDisallowedMethods(t *testing.T) {
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, nil)

	for _, method := range []string{"GET", "PUT", "DELETE", "PATCH", "TRACE"} {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "/reporting-api/csp", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusMethodNotAllowed {
				t.Errorf("expected 405, got %d", rr.Code)
			}
		})
	}
}

func TestGenericReportAPICSPHandlerWellFormedBatch(t *testing.T) {
	rawReport := []byte(`[
    {
        "age": 156165,
        "body": {
            "blockedURL": "inline",
            "disposition": "report",
            "documentURL": "https://integrations.miro.com/asana-cards/miro-plugin.html",
            "effectiveDirective": "script-src-elem",
            "lineNumber": 1,
            "originalPolicy": "default-src 'self'; script-src 'self'; report-to csp-endpoint2;",
            "referrer": "https://miro.com/",
            "sample": "",
            "sourceFile": "https://integrations.miro.com/asana-cards/miro-plugin.html",
            "statusCode": 200
        },
        "type": "csp-violation",
        "url": "https://integrations.miro.com/asana-cards/miro-plugin.html",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    },
    {
        "age": 156165,
        "body": {
            "blockedURL": "https://static.miro-apps.com/integrations/asana-addon/js/miro-plugin.a8cdc6de401c0d820778.js",
            "disposition": "report",
            "documentURL": "https://integrations.miro.com/asana-cards/miro-plugin.html",
            "effectiveDirective": "script-src-elem",
            "originalPolicy": "default-src 'self'; script-src 'self'; report-to csp-endpoint2;",
            "referrer": "https://miro.com/",
            "sample": "",
            "statusCode": 200
        },
        "type": "csp-violation",
        "url": "https://integrations.miro.com/asana-cards/miro-plugin.html",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    },
    {
        "age": 156165,
        "body": {
            "blockedURL": "https://miro.com/app/static/sdk.1.1.js",
            "disposition": "report",
            "documentURL": "https://integrations.miro.com/asana-cards/miro-plugin.html",
            "effectiveDirective": "script-src-elem",
            "originalPolicy": "default-src 'self'; script-src 'self'; report-to csp-endpoint2;",
            "referrer": "https://miro.com/",
            "sample": "",
            "statusCode": 200
        },
        "type": "csp-violation",
        "url": "https://integrations.miro.com/asana-cards/miro-plugin.html",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36"
    }
]`)

	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := NewReportAPICSPHandler(invalidBlockedURIs, nil, false, false, false, false, l, nil)

	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBuffer(rawReport))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for a well-formed batch against non-matching blocked URIs, got %d: %s", rr.Code, rr.Body.String())
	}
}

func TestGenericReportAPICSPHandlerMetricsDecodeError(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, m)
	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBufferString("bad-json"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("reporting_api_csp", "decode_error")); got != 1 {
		t.Fatalf("reports_errors_total decode_error = %v, want 1", got)
	}
}

func TestGenericReportAPICSPHandlerMetricsFilteredURI(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewReportAPICSPHandler([]string{"inline"}, nil, false, false, false, false, l, m)
	body := []byte(`[{"type":"csp-violation","body":{"blockedURL":"inline","documentURL":"https://example.com","disposition":"enforce"}}]`)
	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportFiltered.WithLabelValues("reporting_api_csp", "blocked_uri")); got != 1 {
		t.Fatalf("reports_filtered_total blocked_uri = %v, want 1", got)
	}
}

func TestGenericReportAPICSPHandlerMetricsFilteredDomain(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewReportAPICSPHandler(nil, []string{"evil.example.com"}, false, false, false, false, l, m)
	body := []byte(`[{"type":"csp-violation","body":{"blockedURL":"https://evil.example.com/x.js","documentURL":"https://example.com","disposition":"enforce"}}]`)
	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportFiltered.WithLabelValues("reporting_api_csp", "blocked_domain")); got != 1 {
		t.Fatalf("reports_filtered_total blocked_domain = %v, want 1", got)
	}
}

func TestGenericReportAPICSPHandlerMetricsValidationError(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, m)
	body := []byte(`[{"type":"csp-violation","body":{"blockedURL":"https://cdn.example.com/app.js","documentURL":"about:blank","disposition":"enforce"}}]`)
	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("reporting_api_csp", "validation_error")); got != 1 {
		t.Fatalf("reports_errors_total validation_error = %v, want 1 (should land on ReportErrors, not ReportFiltered)", got)
	}
	if got := testutil.ToFloat64(m.ReportFiltered.WithLabelValues("reporting_api_csp", "validation_error")); got != 0 {
		t.Fatalf("reports_filtered_total validation_error = %v, want 0", got)
	}
}

func TestGenericReportAPICSPHandlerMetricsSuccess(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, m)
	body := []byte(`[{"type":"csp-violation","body":{"blockedURL":"https://cdn.example.com/app.js","documentURL":"https://example.com","disposition":"report"}}]`)
	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("reporting_api_csp", "report_only")); got != 1 {
		t.Fatalf("reports_total report_only = %v, want 1", got)
	}
}

func TestGenericReportAPICSPHandlerSkipsNonCSPViolationReports(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)
	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, nil)

	body := []byte(`[{"type":"deprecation","body":{"blockedURL":"https://example.com/"}}]`)
	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if strings.Contains(logBuf.String(), "document_uri=") {
		t.Errorf("expected no log output for a non-csp-violation report, got: %s", logBuf.String())
	}
}

func TestGenericReportAPICSPHandlerMixedBatchPreservesWellFormedReport(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)
	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, nil)

	payload := []byte(`[
		{"type":"csp-violation","body":{"blockedURL":"https://cdn.example.com/good.js","documentURL":"https://example.com","disposition":"report"}},
		{"type":"csp-violation","body":{"blockedURL":"https://cdn.example.com/bad.js","documentURL":"https://example.com","lineNumber":"not-a-number"}}
	]`)

	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewReader(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	out := logBuf.String()
	if !strings.Contains(out, "good.js") {
		t.Errorf("expected well-formed report to still be logged, got: %s", out)
	}
	if !strings.Contains(out, "item_decode_error") {
		t.Errorf("expected malformed item to be logged with a fallback reason, got: %s", out)
	}
}

func TestGenericReportAPICSPHandlerMetadata(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)
	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, nil)

	body := []byte(`[{"type":"csp-violation","body":{"blockedURL":"https://cdn.example.com/app.js","documentURL":"https://example.com","disposition":"report"}}]`)
	req := httptest.NewRequest("POST", "/reporting-api/csp?metadata=some-tag", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(logBuf.String(), "some-tag") {
		t.Errorf("expected metadata to be logged, got: %s", logBuf.String())
	}
}

func TestGenericReportAPICSPHandlerSetsCORSHeaderOnActualResponse(t *testing.T) {
	// The OPTIONS preflight (ReportAPICorsHandler) has always advertised
	// the requesting origin as allowed, but the actual POST response never
	// carried any CORS headers of its own. Browsers apply the CORS check
	// to the real response too, not just the preflight, so this caused
	// real report deliveries to be rejected client-side as a CORS failure
	// even though the server received and logged them successfully.
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, nil)
	body := []byte(`[{"type":"csp-violation","body":{"blockedURL":"https://cdn.example.com/app.js","documentURL":"https://example.com","disposition":"report"}}]`)
	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBuffer(body))
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("expected Access-Control-Allow-Origin to echo the request origin, got %q", got)
	}
}

func TestGenericReportAPICSPHandlerCORSHeaderPresentOnErrorResponses(t *testing.T) {
	// The CORS header needs to be on every response the handler can
	// produce, not just the 200 path - a browser applies its CORS check
	// regardless of status code.
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, nil)
	req := httptest.NewRequest("POST", "/reporting-api/csp", strings.NewReader("not json"))
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("expected Access-Control-Allow-Origin on the 422 response too, got %q", got)
	}
}

func TestGenericReportAPICSPHandlerCORSFallsBackToWildcardWithNoOrigin(t *testing.T) {
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := NewReportAPICSPHandler(nil, nil, false, false, false, false, l, nil)
	body := []byte(`[{"type":"csp-violation","body":{"blockedURL":"https://cdn.example.com/app.js","documentURL":"https://example.com","disposition":"report"}}]`)
	req := httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewBuffer(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("expected wildcard Access-Control-Allow-Origin with no Origin header, got %q", got)
	}
}

func TestGenericReportAPICSPHandlerJSONUnmarshal(t *testing.T) {
	rawReport := []byte(`{"type":"csp-violation","body":{"blockedURL":"inline"}}`)
	var report ReportAPIReport
	if err := json.Unmarshal(rawReport, &report); err != nil {
		t.Fatalf("unexpected error unmarshalling a single report: %s", err)
	}
	if report.ReportType() != "csp-violation" {
		t.Errorf("expected ReportType() to return %q, got %q", "csp-violation", report.ReportType())
	}
}
