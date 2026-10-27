package handler

import (
	"bytes"
	"encoding/json"
	"errors"
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

// testReport is a minimal ReportTyped implementation used to exercise
// BatchReportHandler directly, independent of any real handler's business
// logic.
type testReport struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

func (t testReport) ReportType() string { return t.Type }

func passthroughProcess(report testReport) ProcessResult {
	return ProcessResult{Fields: Fields{"value": report.Value}, Mode: "enforced"}
}

func TestBatchReportHandlerDisallowedMethod(t *testing.T) {
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: newTestMetrics()}}

	req := httptest.NewRequest("GET", "/batch", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rr.Code)
	}
}

func TestBatchReportHandlerDecodesArray(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: newTestMetrics()}}

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
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: newTestMetrics()}}

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
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`{"type":"x","value":"one"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for a bare object without SingleObject, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "decode_error")); got != 1 {
		t.Fatalf("reports_errors_total decode_error = %v, want 1", got)
	}
}

func TestBatchReportHandlerSingleObjectAccepted(t *testing.T) {
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", SingleObject: true, Process: passthroughProcess, Options: Options{Logger: l, Metrics: newTestMetrics()}}

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

func TestBatchReportHandlerSingleObjectRejectsOtherBodies(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{name: "malformed_json", body: "not json at all"},
		{name: "array", body: `[{"type":"x","value":"one"}]`},
		{name: "mistyped_field", body: `{"type":"x","value":123}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			m := metrics.New(registry)
			l, buf := newTestLogger()
			h := &BatchReportHandler[testReport]{HandlerName: "test", SingleObject: true, Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

			req := httptest.NewRequest("POST", "/batch", strings.NewReader(tt.body))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("expected 422, got %d", rr.Code)
			}
			if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "decode_error")); got != 1 {
				t.Errorf("reports_errors_total decode_error = %v, want 1", got)
			}
			if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "item_decode_error")); got != 0 {
				t.Errorf("reports_errors_total item_decode_error = %v, want 0", got)
			}
			if buf.Len() != 0 {
				t.Errorf("expected no log output at info level, got: %s", buf.String())
			}
		})
	}
}

func TestBatchReportHandlerBodyReadError(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

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

// The report endpoints have to be public, so a body over the limit is
// rejected without being read into memory, and nothing in it is logged.
func TestBatchReportHandlerBodyTooLarge(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, buf := newTestLoggerAtLevel(slog.LevelDebug)
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

	body := `[{"type":"x","value":"` + strings.Repeat("a", maxBodyBytes) + `"}]`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/batch", strings.NewReader(body)))

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "body_too_large")); got != 1 {
		t.Errorf("reports_errors_total body_too_large = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "decode_error")); got != 0 {
		t.Errorf("reports_errors_total decode_error = %v, want 0", got)
	}
	if strings.Contains(buf.String(), "value=") {
		t.Errorf("expected nothing from the oversized batch to be logged, got: %s", buf.String())
	}
}

func TestBatchReportHandlerBodyAtLimitIsAccepted(t *testing.T) {
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: newTestMetrics()}}

	prefix, suffix := `[{"type":"x","value":"`, `"}]`
	body := prefix + strings.Repeat("a", maxBodyBytes-len(prefix)-len(suffix)) + suffix
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/batch", strings.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 for a body exactly at the limit, got %d", rr.Code)
	}
}

type errReader struct{}

func (errReader) Read(p []byte) (int, error) { return 0, errors.New("simulated read failure") }

func TestBatchReportHandlerItemDecodeErrorSkipsAndContinues(t *testing.T) {
	l, buf := newTestLoggerAtLevel(slog.LevelDebug)
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: newTestMetrics()}}

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

// Malformed items are usually garbage or hostile, so logging them must be
// an explicit opt-in via debug level rather than noise at the default level.
func TestBatchReportHandlerItemDecodeErrorLogLevel(t *testing.T) {
	tests := []struct {
		name        string
		level       slog.Level
		wantEntries []logEntry
	}{
		{
			name:        "hidden_at_info",
			level:       slog.LevelInfo,
			wantEntries: nil,
		},
		{
			name:  "logged_at_debug",
			level: slog.LevelDebug,
			wantEntries: []logEntry{{
				Level:   slog.LevelDebug,
				Message: "skipping a report that couldn't be decoded",
				Data: Fields{
					"reason": "item_decode_error",
					"body":   `{"type":"x","value":123}`,
					"path":   "/batch",
				},
			}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, rec := newRecordingLogger(tt.level)
			h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: newTestMetrics()}}

			req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":123}]`))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
			if got := rec.Entries(); !reflect.DeepEqual(got, tt.wantEntries) {
				t.Errorf("log entries = %+v, want %+v", got, tt.wantEntries)
			}
		})
	}
}

func TestBatchReportHandlerItemDecodeErrorMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

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
	h := &BatchReportHandler[testReport]{HandlerName: "test", ExpectedType: "wanted", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

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

func TestBatchReportHandlerValidateRejectedCountsAsError(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{
		HandlerName: "test",
		Process:     passthroughProcess,
		Validate: func(item testReport) *Rejection {
			return &Rejection{Reason: "some_reason", Err: errors.New("rejected")}
		},
		Options: Options{Logger: l, Metrics: m},
	}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "some_reason")); got != 1 {
		t.Fatalf("reports_errors_total some_reason = %v, want 1", got)
	}
}

func TestBatchReportHandlerValidateFilteredCountsAsFiltered(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{
		HandlerName: "test",
		Process:     passthroughProcess,
		Validate: func(item testReport) *Rejection {
			return &Rejection{Reason: "some_reason", Filtered: true, Err: errors.New("filtered")}
		},
		Options: Options{Logger: l, Metrics: m},
	}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := testutil.ToFloat64(m.ReportFiltered.WithLabelValues("test", "some_reason")); got != 1 {
		t.Errorf("reports_filtered_total some_reason = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "some_reason")); got != 0 {
		t.Errorf("reports_errors_total some_reason = %v, want 0, a filtered report isn't an error", got)
	}
}

// A rejected report in a batch is skipped, not fatal. Under the Reporting
// API any non-2xx response is an upload failure: the browser discards every
// report in the batch and backs off the endpoint, so one filtered report
// must not take the well-formed ones down with it.
func TestBatchReportHandlerValidateSkipsRejectedItemInBatch(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, rec := newRecordingLogger(slog.LevelInfo)
	h := &BatchReportHandler[testReport]{
		HandlerName: "test",
		Process:     passthroughProcess,
		Validate: func(item testReport) *Rejection {
			if item.Value == "bad" {
				return &Rejection{Reason: "some_reason", Err: errors.New("rejected")}
			}
			return nil
		},
		Options: Options{Logger: l, Metrics: m},
	}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"good"},{"type":"x","value":"bad"}]`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	wantData := Fields{"value": "good", "metadata": nil, "path": "/batch"}
	got := rec.Entries()
	if len(got) != 1 || !reflect.DeepEqual(got[0].Data, wantData) {
		t.Fatalf("expected only the good report logged as %v, got %v", wantData, got)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "some_reason")); got != 1 {
		t.Errorf("reports_errors_total some_reason = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.Reports.WithLabelValues("test", "enforced")); got != 1 {
		t.Errorf("reports_total = %v, want 1", got)
	}
}

func TestBatchReportHandlerValidateRejectsSingleObject(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, buf := newTestLogger()
	h := &BatchReportHandler[testReport]{
		HandlerName:  "test",
		SingleObject: true,
		Process:      passthroughProcess,
		Validate: func(item testReport) *Rejection {
			return &Rejection{Reason: "some_reason", Err: errors.New("rejected")}
		},
		Options: Options{Logger: l, Metrics: m},
	}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`{"type":"x","value":"one"}`))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if rr.Body.String() != "rejected\n" {
		t.Errorf("response body = %q, want %q", rr.Body.String(), "rejected\n")
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "some_reason")); got != 1 {
		t.Errorf("reports_errors_total some_reason = %v, want 1", got)
	}
	if buf.Len() != 0 {
		t.Errorf("expected nothing logged at info level, got: %s", buf.String())
	}
}

func TestBatchReportHandlerDefaultSuccessMetric(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

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
		Process:             passthroughProcess,
		RecordSuccessMetric: func(mode string) { overrideCalledWith = mode },
		Options:             Options{Logger: l, Metrics: m},
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
		Process:     passthroughProcess,
		SetResponseHeaders: func(w http.ResponseWriter, r *http.Request) {
			called = true
			w.Header().Set("X-Test-Header", "present")
		},
		Options: Options{Logger: l, Metrics: newTestMetrics()},
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
		h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: newTestMetrics()}}

		req := httptest.NewRequest("POST", "/batch?metadata=env-prod", strings.NewReader(`[{"type":"x","value":"one"}]`))
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)

		if !strings.Contains(buf.String(), "env-prod") {
			t.Errorf("expected metadata string to be logged, got: %s", buf.String())
		}
	})

	t.Run("object", func(t *testing.T) {
		l, buf := newTestLogger()
		h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{MetadataObject: true, Logger: l, Metrics: newTestMetrics()}}

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
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{ClientIP: ClientIPFull, Logger: l, Metrics: newTestMetrics()}}

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
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{ClientIP: ClientIPTruncated, Logger: l, Metrics: newTestMetrics()}}

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
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{ClientIP: ClientIPFull, Logger: l, Metrics: newTestMetrics()}}

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
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{ClientIP: ClientIPTruncated, Logger: l, Metrics: newTestMetrics()}}

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

// newTestMetrics returns metrics on a fresh registry, for tests that don't
// inspect them.
func newTestMetrics() *metrics.Metrics {
	return metrics.New(prometheus.NewRegistry())
}

// The address belongs to the request, so a batch from an address that
// can't be parsed warns once rather than once for every report in it.
func TestBatchReportHandlerClientIPParseErrorWarnsOncePerRequest(t *testing.T) {
	l, rec := newRecordingLogger(slog.LevelInfo)
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{ClientIP: ClientIPFull, Logger: l, Metrics: newTestMetrics()}}

	req := httptest.NewRequest("POST", "/batch", strings.NewReader(`[{"type":"x","value":"one"},{"type":"x","value":"two"}]`))
	req.RemoteAddr = "not-a-valid-address"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	want := []logEntry{
		{
			Level:   slog.LevelWarn,
			Message: "unable to parse client ip",
			Data:    Fields{"error": "unable to parse remote address not-a-valid-address: not an ip:port"},
		},
		{Level: slog.LevelInfo, Data: Fields{"value": "one", "metadata": nil, "path": "/batch"}},
		{Level: slog.LevelInfo, Data: Fields{"value": "two", "metadata": nil, "path": "/batch"}},
	}
	got := rec.Entries()
	for i := range got {
		if err, ok := got[i].Data["error"].(error); ok {
			got[i].Data["error"] = err.Error()
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("log entries = %+v, want %+v", got, want)
	}
}

// BenchmarkBatchReportHandlerFullBatch posts the largest batch a browser
// sends: 100 CSP reports, each repeating a long policy.
func BenchmarkBatchReportHandlerFullBatch(b *testing.B) {
	report := ReportAPIReport{
		Type: "csp-violation",
		URL:  "https://example.com/",
		Body: ReportAPIViolation{
			BlockedURL:     "https://evil.example/x.js",
			DocumentURL:    "https://example.com/",
			OriginalPolicy: strings.Repeat("script-src 'self' https://cdn.example.com; ", 750),
		},
	}
	reports := make([]ReportAPIReport, 100)
	for i := range reports {
		reports[i] = report
	}
	body, err := json.Marshal(reports)
	if err != nil {
		b.Fatal(err)
	}

	h := NewReportAPICSPHandler(Filter{}, Options{Logger: slog.New(slog.DiscardHandler), Metrics: newTestMetrics()})
	b.SetBytes(int64(len(body)))
	b.ReportAllocs()
	for b.Loop() {
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/csp", bytes.NewReader(body)))
		if rr.Code != http.StatusOK {
			b.Fatalf("expected 200, got %d", rr.Code)
		}
	}
}

// Reports are only logged once the whole body has decoded, so a body that
// breaks partway through logs nothing rather than the reports before the
// break. A browser retries a failed upload, which would log them twice.
func TestBatchReportHandlerMalformedBodyLogsNothing(t *testing.T) {
	tests := []struct {
		name         string
		singleObject bool
		body         string
	}{
		{name: "empty", body: ``},
		{name: "object_not_array", body: `{"type":"x","value":"one"}`},
		{name: "syntax_error_mid_array", body: `[{"type":"x","value":"one"}, nope]`},
		{name: "truncated_array", body: `[{"type":"x","value":"one"},`},
		{name: "unclosed_array", body: `[{"type":"x","value":"one"}`},
		{name: "data_after_array", body: `[{"type":"x","value":"one"}] trailing`},
		{name: "second_array", body: `[{"type":"x","value":"one"}][]`},
		{name: "single_empty", singleObject: true, body: ``},
		{name: "single_data_after_object", singleObject: true, body: `{"type":"x","value":"one"} trailing`},
		{name: "single_second_object", singleObject: true, body: `{"type":"x","value":"one"}{}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prometheus.NewRegistry()
			m := metrics.New(registry)
			l, rec := newRecordingLogger(slog.LevelInfo)
			h := &BatchReportHandler[testReport]{HandlerName: "test", SingleObject: tt.singleObject, Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest("POST", "/batch", strings.NewReader(tt.body)))

			if rr.Code != http.StatusUnprocessableEntity {
				t.Fatalf("expected 422, got %d", rr.Code)
			}
			if got := rec.Entries(); len(got) != 0 {
				t.Errorf("expected nothing logged, got %+v", got)
			}
			if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "decode_error")); got != 1 {
				t.Errorf("reports_errors_total decode_error = %v, want 1", got)
			}
		})
	}
}

func TestTruncateQueryStringFragment(t *testing.T) {
	tests := []struct {
		name string
		uri  string
		want string
	}{
		{name: "query_and_fragment", uri: "http://localhost.com/?test#anchor", want: "http://localhost.com/"},
		{name: "neither", uri: "http://example.invalid", want: "http://example.invalid"},
		{name: "fragment", uri: "http://example.invalid#a", want: "http://example.invalid"},
		{name: "query", uri: "http://example.invalid?a", want: "http://example.invalid"},
		{name: "fragment_before_query", uri: "http://example.invalid#b?a", want: "http://example.invalid"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateQueryStringFragment(tt.uri); got != tt.want {
				t.Errorf("truncateQueryStringFragment(%q) = %q, want %q", tt.uri, got, tt.want)
			}
		})
	}
}
