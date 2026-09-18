package handler

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

// testReport is a minimal ReportTyped implementation used to exercise
// BatchReportHandler directly, independent of any real handler's business
// logic.
type testReport struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (t testReport) ReportType() string { return t.Type }

func newTestLogger() (*logrus.Logger, *bytes.Buffer) {
	l := logrus.New()
	var buf bytes.Buffer
	l.SetOutput(&buf)
	return l, &buf
}

func passthroughProcess(report testReport, r *http.Request, metadata interface{}) ProcessResult {
	return ProcessResult{
		Fields: logrus.Fields{"value": report.Value, "metadata": metadata, "path": r.URL.Path},
		Mode:   "enforced",
	}
}

func TestBatchReportHandlerDisallowedMethod(t *testing.T) {
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("GET", "/batch", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestBatchReportHandlerDecodesArray(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"},{"type":"x","value":"two"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if !strings.Contains(buf.String(), "value=one") || !strings.Contains(buf.String(), "value=two") {
		t.Errorf("expected both items logged, got: %s", buf.String())
	}
}

func TestBatchReportHandlerEmptyArrayIsNoOp(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if buf.Len() != 0 {
		t.Errorf("expected no log output for an empty batch, got: %s", buf.String())
	}
}

func TestBatchReportHandlerSingleObjectRejectedByDefault(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Metrics: m, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`{"type":"x","value":"one"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for a bare object without AllowSingleObject, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "decode_error")); got != 1 {
		t.Fatalf("reports_errors_total decode_error = %v, want 1", got)
	}
}

func TestBatchReportHandlerSingleObjectAcceptedWhenAllowed(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", AllowSingleObject: true, Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`{"type":"x","value":"one"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	if !strings.Contains(buf.String(), "value=one") {
		t.Errorf("expected the single object to be processed, got: %s", buf.String())
	}
}

func TestBatchReportHandlerMalformedJSONAlwaysRejected(t *testing.T) {
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", AllowSingleObject: true, Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader("not json at all"))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for genuinely malformed JSON even with AllowSingleObject, got %d", rr.Code)
	}
}

func TestBatchReportHandlerBodyReadError(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Metrics: m, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", errReader{})
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 when the body can't be read, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "decode_error")); got != 1 {
		t.Fatalf("reports_errors_total decode_error = %v, want 1", got)
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errors.New("simulated read failure") }

func TestBatchReportHandlerItemDecodeErrorSkipsAndContinues(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"good"},{"type":"x","value":123}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	out := buf.String()
	if !strings.Contains(out, "value=good") {
		t.Errorf("expected the well-formed item to still be processed, got: %s", out)
	}
	if !strings.Contains(out, "item_decode_error") {
		t.Errorf("expected the malformed item to be logged with item_decode_error, got: %s", out)
	}
}

func TestBatchReportHandlerItemDecodeErrorMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Metrics: m, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":123}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "item_decode_error")); got != 1 {
		t.Fatalf("reports_errors_total item_decode_error = %v, want 1", got)
	}
}

func TestBatchReportHandlerExpectedTypeSkipsAndIncrementsIgnored(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", ExpectedType: "wanted", Logger: l, Metrics: m, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"unwanted","value":"skip-me"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if strings.Contains(buf.String(), "skip-me") {
		t.Errorf("expected the unexpected-type item not to be processed, got: %s", buf.String())
	}
	if got := testutil.ToFloat64(m.ReportIgnored.WithLabelValues("test", "unsupported_type")); got != 1 {
		t.Fatalf("reports_ignored_total = %v, want 1", got)
	}
}

func TestBatchReportHandlerValidateRejectsWithDefaultMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{
		HandlerName: "test",
		Logger:      l,
		Metrics:     m,
		Process:     passthroughProcess,
		Validate: func(items []testReport) (string, error) {
			return "some_reason", errors.New("rejected")
		},
	}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "some_reason")); got != 1 {
		t.Fatalf("reports_errors_total some_reason = %v, want 1 (default fallback metric)", got)
	}
}

func TestBatchReportHandlerValidateRejectsWithOverrideMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	var overrideCalledWith string
	h := &BatchReportHandler[testReport]{
		HandlerName: "test",
		Logger:      l,
		Metrics:     m,
		Process:     passthroughProcess,
		Validate: func(items []testReport) (string, error) {
			return "some_reason", errors.New("rejected")
		},
		RecordValidationErrorMetric: func(reason string) {
			overrideCalledWith = reason
		},
	}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if overrideCalledWith != "some_reason" {
		t.Fatalf("expected RecordValidationErrorMetric to be called with %q, got %q", "some_reason", overrideCalledWith)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "some_reason")); got != 0 {
		t.Fatalf("reports_errors_total some_reason = %v, want 0 (override should replace the default, not add to it)", got)
	}
}

func TestBatchReportHandlerDefaultSuccessMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Metrics: m, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("test", "enforced")); got != 1 {
		t.Fatalf("reports_total = %v, want 1 (default fallback metric)", got)
	}
}

func TestBatchReportHandlerOverrideSuccessMetricTakesPrecedence(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	var overrideCalledWith string
	h := &BatchReportHandler[testReport]{
		HandlerName:         "test",
		Logger:              l,
		Metrics:             m,
		Process:             passthroughProcess,
		RecordSuccessMetric: func(mode string) { overrideCalledWith = mode },
	}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if overrideCalledWith != "enforced" {
		t.Fatalf("expected RecordSuccessMetric to be called with %q, got %q", "enforced", overrideCalledWith)
	}
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("test", "enforced")); got != 0 {
		t.Fatalf("reports_total = %v, want 0 (override should replace the default, not add to it)", got)
	}
}

func TestBatchReportHandlerSetResponseHeadersRunsBeforeMethodCheck(t *testing.T) {
	l, _ := newTestLogger()
	called := false
	h := &BatchReportHandler[testReport]{
		HandlerName: "test",
		Logger:      l,
		Process:     passthroughProcess,
		SetResponseHeaders: func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.Header().Set("X-Test-Header", "present")
		},
	}

	req := httptest.NewRequest("GET", "/batch", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
	if !called {
		t.Fatal("expected SetResponseHeaders to run even for a disallowed method")
	}
	if got := rr.Header().Get("X-Test-Header"); got != "present" {
		t.Fatalf("expected X-Test-Header to be set on the 405 response, got %q", got)
	}
}

func TestBatchReportHandlerMetadata(t *testing.T) {
	t.Run("single string", func(t *testing.T) {
		l, buf := newTestLogger()
		h := &BatchReportHandler[testReport]{HandlerName: "test", Logger: l, Process: passthroughProcess}

		req := httptest.NewRequest("POST", "/batch?metadata=env-prod", strings.NewReader(`[{"type":"x","value":"one"}]`))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if !strings.Contains(buf.String(), "env-prod") {
			t.Errorf("expected metadata string to be logged, got: %s", buf.String())
		}
	})

	t.Run("object", func(t *testing.T) {
		l, buf := newTestLogger()
		h := &BatchReportHandler[testReport]{HandlerName: "test", MetadataObject: true, Logger: l, Process: passthroughProcess}

		req := httptest.NewRequest("POST", "/batch?env=prod&team=platform", strings.NewReader(`[{"type":"x","value":"one"}]`))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		out := buf.String()
		if !strings.Contains(out, "env:prod") || !strings.Contains(out, "team:platform") {
			t.Errorf("expected metadata object to be logged, got: %s", out)
		}
	})
}

func TestBatchReportHandlerLogClientIP(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", LogClientIP: true, Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	req.RemoteAddr = "203.0.113.7:54321"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !strings.Contains(buf.String(), "client_ip=203.0.113.7") {
		t.Errorf("expected full client_ip to be logged, got: %s", buf.String())
	}
}

func TestBatchReportHandlerLogTruncatedClientIP(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", LogTruncatedClientIP: true, Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	req.RemoteAddr = "203.0.113.7:54321"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if !strings.Contains(buf.String(), "client_ip=203.0.113.0/24") {
		t.Errorf("expected truncated client_ip to be logged, got: %s", buf.String())
	}
}

func TestBatchReportHandlerLogClientIPParseErrorIsNonFatal(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", LogClientIP: true, Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	req.RemoteAddr = "not-a-valid-address"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 even when the client IP can't be parsed, got %d", rr.Code)
	}
	if strings.Contains(buf.String(), "client_ip=") {
		t.Errorf("expected no client_ip field when parsing fails, got: %s", buf.String())
	}
}

func TestBatchReportHandlerLogTruncatedClientIPParseErrorIsNonFatal(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", LogTruncatedClientIP: true, Logger: l, Process: passthroughProcess}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	req.RemoteAddr = "not-a-valid-address"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 even when the client IP can't be parsed, got %d", rr.Code)
	}
	if strings.Contains(buf.String(), "client_ip=") {
		t.Errorf("expected no client_ip field when parsing fails, got: %s", buf.String())
	}
}
