package handler

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

func TestReportAPICspReport(t *testing.T) {
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

	var reports_raw []ReportAPIReport
	jsonErr := json.Unmarshal(rawReport, &reports_raw)
	if jsonErr != nil {
		fmt.Println("error:", jsonErr)
	}

	reports := ReportAPIReports{
		Reports: reports_raw,
	}

	reportApiViolationHandler := &ReportAPIViolationReportHandler{BlockedURIs: invalidBlockedURIs}
	validateErr := reportApiViolationHandler.validateViolation(reports)
	if validateErr != nil {
		t.Errorf("expected error not be raised")
	}
}

func TestReportAPIHandlerMetricsDecodeError(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := &ReportAPIViolationReportHandler{Logger: l, Metrics: m}
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

func TestReportAPIHandlerMetricsFilteredURI(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := &ReportAPIViolationReportHandler{
		Logger:      l,
		Metrics:     m,
		BlockedURIs: []string{"inline"},
	}
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

func TestReportAPIHandlerMetricsSuccess(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))

	h := &ReportAPIViolationReportHandler{Logger: l, Metrics: m}
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
