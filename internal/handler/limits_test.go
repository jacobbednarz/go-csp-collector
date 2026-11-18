package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

// emptyReports is a batch of n empty objects, the cheapest body that still
// decodes into n full reports.
func emptyReports(n int) string {
	return "[" + strings.TrimSuffix(strings.Repeat("{},", n), ",") + "]"
}

func TestBatchReportHandlerReportsPerRequestLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		reports  int
		wantCode int
	}{
		{name: "at_limit", reports: maxReportsPerRequest, wantCode: http.StatusOK},
		{name: "over_limit", reports: maxReportsPerRequest + 1, wantCode: http.StatusRequestEntityTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l, buf := newTestLogger()
			m := newTestMetrics()
			h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

			req := httptest.NewRequest("POST", "/batch", strings.NewReader(emptyReports(tt.reports)))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantCode)
			}
			wantErrors := 0.0
			if tt.wantCode != http.StatusOK {
				wantErrors = 1
				// Nothing is logged until the whole body is accepted.
				if buf.Len() != 0 {
					t.Errorf("expected no report logged, got: %s", buf.String())
				}
			}
			if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "too_many_reports")); got != wantErrors {
				t.Errorf("too_many_reports = %v, want %v", got, wantErrors)
			}
		})
	}
}

// Undecodable items count toward the limit too, or a body of them could
// still be arbitrarily long.
func TestBatchReportHandlerReportsPerRequestLimitCountsUndecodableItems(t *testing.T) {
	t.Parallel()

	l, _ := newTestLogger()
	m := newTestMetrics()
	h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

	body := "[" + strings.TrimSuffix(strings.Repeat("0,", maxReportsPerRequest+1), ",") + "]"
	req := httptest.NewRequest("POST", "/batch", strings.NewReader(body))
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusRequestEntityTooLarge)
	}
}

// The query is logged with every report in the request, so a long one
// multiplies the log output by the number of reports.
func TestBatchReportHandlerQueryLimit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		query    string
		wantCode int
	}{
		{name: "at_limit", query: "metadata=" + strings.Repeat("a", maxQueryBytes-len("metadata=")), wantCode: http.StatusOK},
		{name: "over_limit", query: "metadata=" + strings.Repeat("a", maxQueryBytes), wantCode: http.StatusRequestURITooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			l, buf := newTestLogger()
			m := newTestMetrics()
			h := &BatchReportHandler[testReport]{HandlerName: "test", Process: passthroughProcess, Options: Options{Logger: l, Metrics: m}}

			req := httptest.NewRequest("POST", "/batch?"+tt.query, strings.NewReader(`[{"type":"x","value":"one"}]`))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != tt.wantCode {
				t.Fatalf("status = %d, want %d", rr.Code, tt.wantCode)
			}
			wantErrors := 0.0
			if tt.wantCode != http.StatusOK {
				wantErrors = 1
				if buf.Len() != 0 {
					t.Errorf("expected no report logged, got: %s", buf.String())
				}
			}
			if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("test", "query_too_long")); got != wantErrors {
				t.Errorf("query_too_long = %v, want %v", got, wantErrors)
			}
		})
	}
}

// status-code has been sent as both a number and a string, so only JSON
// scalars are kept. An array or object, which no browser sends, is logged as
// null rather than decoded, since decoding a large one costs many times its
// size in memory.
func TestCSPStatusCodeKeepsOnlyScalars(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		statusCode string
		want       string
	}{
		{name: "number", statusCode: `200`, want: "status_code=200"},
		{name: "string", statusCode: `"200"`, want: "status_code=200"},
		{name: "null", statusCode: `null`, want: "status_code=<nil>"},
		{name: "array", statusCode: `[{},{},[1,2,3]]`, want: "status_code=<nil>"},
		{name: "object", statusCode: `{"a":{"b":[]}}`, want: "status_code=<nil>"},
		{name: "missing", want: "status_code=<nil>"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			field := ""
			if tt.statusCode != "" {
				field = `,"status-code":` + tt.statusCode
			}
			body := `{"csp-report":{"document-uri":"https://example.com","blocked-uri":"inline"` + field + `}}`

			l, buf := newTestLogger()
			h := newTestCSPHandler(nil, nil, l, newTestMetrics())
			req := httptest.NewRequest("POST", "/csp", strings.NewReader(body))
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d", rr.Code, http.StatusOK)
			}
			if !strings.Contains(buf.String(), tt.want+" ") {
				t.Errorf("expected %q in log, got: %s", tt.want, buf.String())
			}
		})
	}
}
