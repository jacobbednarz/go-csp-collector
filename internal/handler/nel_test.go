package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func newNELHandler(reportOnly bool) *NELViolationReportHandler { //nolint:unparam
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	return &NELViolationReportHandler{
		ReportOnly: reportOnly,
		Logger:     l,
	}
}

func TestNELValidateReportsValidURL(t *testing.T) {
	h := newNELHandler(false)
	reports := sampleNELReport("https://example.com/page")
	if err := h.validateReports(reports); err != nil {
		t.Errorf("expected no error, got: %s", err)
	}
}

func TestNELValidateReportsInvalidURL(t *testing.T) {
	h := newNELHandler(false)
	reports := sampleNELReport("about:blank")
	err := h.validateReports(reports)
	if err == nil {
		t.Fatal("expected error but got nil")
	}
	if !strings.Contains(err.Error(), "url ('about:blank') is invalid") {
		t.Errorf("unexpected error message: %s", err)
	}
}

func TestNELValidateReportsSkipsNonNetworkError(t *testing.T) {
	h := newNELHandler(false)
	reports := []NELReport{
		{
			Type: "csp-violation",
			URL:  "about:blank", // would fail validation if not skipped
		},
	}
	if err := h.validateReports(reports); err != nil {
		t.Errorf("non-network-error type should be skipped, got: %s", err)
	}
}

func TestNELHandlerDisallowedMethods(t *testing.T) {
	h := newNELHandler(false)
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

func TestNELHandlerInvalidJSON(t *testing.T) {
	l := logrus.New()
	l.SetOutput(bytes.NewBuffer(nil))
	h := &NELViolationReportHandler{Logger: l}

	req := httptest.NewRequest("POST", "/nel", strings.NewReader("not json"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("expected 422, got %d", rr.Code)
	}
}

func TestNELHandlerInvalidURLReturns400(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)
	h := &NELViolationReportHandler{Logger: l}

	payload, _ := json.Marshal(sampleNELReport("about:blank"))
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected 400, got %d", rr.Code)
	}
}

func TestNELHandlerLogsReportOnlyTrue(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)

	h := &NELViolationReportHandler{ReportOnly: true, Logger: l}

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

func TestNELHandlerLogsReportOnlyFalse(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)

	h := &NELViolationReportHandler{ReportOnly: false, Logger: l}

	payload, _ := json.Marshal(sampleNELReport("https://example.com/page"))
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(logBuf.String(), "report_only=false") {
		t.Errorf("expected report_only=false in log output, got: %s", logBuf.String())
	}
}

func TestNELHandlerLogsExpectedFields(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)

	h := &NELViolationReportHandler{Logger: l}
	payload, _ := json.Marshal(sampleNELReport("https://example.com/page"))
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := logBuf.String()
	for _, field := range []string{"url=", "type=", "phase=", "protocol=", "method=", "status_code=", "elapsed_time=", "server_ip=", "sampling_fraction="} {
		if !strings.Contains(out, field) {
			t.Errorf("expected field %q in log output, got: %s", field, out)
		}
	}
}

func TestNELHandlerSkipsNonNetworkErrorReports(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)

	h := &NELViolationReportHandler{Logger: l}

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
	// Nothing should be logged since the only report was skipped.
	if strings.Contains(logBuf.String(), "url=") {
		t.Errorf("expected no log output for non-network-error report, got: %s", logBuf.String())
	}
}

func TestNELHandlerMultipleReports(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)

	h := &NELViolationReportHandler{Logger: l}

	reports := []NELReport{
		{Type: "network-error", URL: "https://example.com/a", Body: NELReportBody{Type: "tcp.refused", Phase: "connection"}},
		{Type: "network-error", URL: "https://example.com/b", Body: NELReportBody{Type: "dns.unreachable", Phase: "dns"}},
	}
	payload, _ := json.Marshal(reports)
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := logBuf.String()
	if !strings.Contains(out, "example.com/a") {
		t.Errorf("expected first report URL in log output")
	}
	if !strings.Contains(out, "example.com/b") {
		t.Errorf("expected second report URL in log output")
	}
}

func TestNELHandlerMetadataString(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)

	h := &NELViolationReportHandler{Logger: l}
	payload, _ := json.Marshal(sampleNELReport("https://example.com/page"))
	req := httptest.NewRequest("POST", "/nel?metadata=myvalue", bytes.NewBuffer(payload))
	h.ServeHTTP(httptest.NewRecorder(), req)

	if !strings.Contains(logBuf.String(), "metadata=myvalue") {
		t.Errorf("expected metadata=myvalue in log output, got: %s", logBuf.String())
	}
}

func TestNELHandlerMetadataObject(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)

	h := &NELViolationReportHandler{Logger: l, MetadataObject: true}
	payload, _ := json.Marshal(sampleNELReport("https://example.com/page"))
	req := httptest.NewRequest("POST", "/nel?a=1&b=2", bytes.NewBuffer(payload))
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := logBuf.String()
	if !strings.Contains(out, "metadata=") {
		t.Errorf("expected metadata field in log output, got: %s", out)
	}
	if !strings.Contains(out, "a:1") && !strings.Contains(out, "a=1") {
		t.Errorf("expected query param 'a' in metadata, got: %s", out)
	}
}

func TestNELHandlerTruncateQueryStringFragment(t *testing.T) {
	var logBuf bytes.Buffer
	l := logrus.New()
	l.SetOutput(&logBuf)

	h := &NELViolationReportHandler{Logger: l, TruncateQueryStringFragment: true}

	reports := []NELReport{
		{
			Type: "network-error",
			URL:  "https://example.com/page?secret=123",
			Body: NELReportBody{
				Type:     "ok",
				Phase:    "application",
				Referrer: "https://example.com/ref?token=abc",
			},
		},
	}
	payload, _ := json.Marshal(reports)
	req := httptest.NewRequest("POST", "/nel", bytes.NewBuffer(payload))
	h.ServeHTTP(httptest.NewRecorder(), req)

	out := logBuf.String()
	if strings.Contains(out, "secret=123") {
		t.Errorf("URL query string should have been truncated, got: %s", out)
	}
	if strings.Contains(out, "token=abc") {
		t.Errorf("referrer query string should have been truncated, got: %s", out)
	}
	if !strings.Contains(out, "example.com/page") {
		t.Errorf("expected base URL in log output, got: %s", out)
	}
}
