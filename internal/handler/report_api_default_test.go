package handler

import (
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

// The default endpoint takes every report type in one batch and logs the
// body as raw JSON, since its shape depends on the type.
func TestReportAPIDefaultHandlerLogsEveryType(t *testing.T) {
	l, rec := newRecordingLogger(slog.LevelInfo)
	h := NewReportAPIDefaultHandler(false, false, false, false, l, nil)

	body := `[
		{"type":"deprecation","url":"https://example.com/a?q=1","age":5,"user_agent":"t","body":{"id":"UnloadHandler","message":"unload is deprecated","lineNumber":3}},
		{"type":"permissions-policy-violation","url":"https://example.com/b","body":{"featureId":"geolocation","disposition":"enforce"}},
		{"type":"made-up","url":"https://example.com/c"}
	]`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/default", strings.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	want := []Fields{
		{"type": "deprecation", "url": "https://example.com/a?q=1", "body": `{"id":"UnloadHandler","message":"unload is deprecated","lineNumber":3}`, "metadata": nil, "path": "/reporting-api/default"},
		{"type": "permissions-policy-violation", "url": "https://example.com/b", "body": `{"featureId":"geolocation","disposition":"enforce"}`, "metadata": nil, "path": "/reporting-api/default"},
		{"type": "made-up", "url": "https://example.com/c", "body": "", "metadata": nil, "path": "/reporting-api/default"},
	}
	entries := rec.Entries()
	if len(entries) != len(want) {
		t.Fatalf("got %d log entries, want %d", len(entries), len(want))
	}
	for i := range want {
		if !reflect.DeepEqual(entries[i].Data, want[i]) {
			t.Errorf("entry %d fields = %v, want %v", i, entries[i].Data, want[i])
		}
	}
}

// URLs inside the raw body can't be found reliably to strip, so with
// --truncate-query-fragment the body is left out rather than logged with
// query strings the operator asked to have removed.
func TestReportAPIDefaultHandlerTruncationOmitsBody(t *testing.T) {
	l, rec := newRecordingLogger(slog.LevelInfo)
	h := NewReportAPIDefaultHandler(true, false, false, false, l, nil)

	body := `[{"type":"deprecation","url":"https://example.com/a?q=1#f","body":{"sourceFile":"https://example.com/app.js?token=secret"}}]`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/default", strings.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	want := Fields{"type": "deprecation", "url": "https://example.com/a", "metadata": nil, "path": "/reporting-api/default"}
	entries := rec.Entries()
	if len(entries) != 1 || !reflect.DeepEqual(entries[0].Data, want) {
		t.Fatalf("log entries = %v, want one entry with %v", entries, want)
	}
}

// The metric mode label is the report type when it's a known Reporting API
// type, and "reporting-api-default" otherwise. The type is client
// controlled, so labelling with it directly would let anyone create
// unlimited metric series.
func TestReportAPIDefaultHandlerMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := NewReportAPIDefaultHandler(false, false, false, false, l, m)

	body := `[
		{"type":"deprecation","url":"https://example.com/"},
		{"type":"intervention","url":"https://example.com/"},
		{"type":"made-up","url":"https://example.com/"},
		{"type":"another-made-up","url":"https://example.com/"},
		{"type":"deprecation","url":"about:blank"}
	]`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/default", strings.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := testutil.CollectAndCount(m.Reports); got != 3 {
		t.Errorf("reports_total has %d series, want 3", got)
	}
	for _, c := range []struct {
		mode string
		want float64
	}{
		{"deprecation", 1},
		{"intervention", 1},
		{"reporting-api-default", 2},
	} {
		if got := testutil.ToFloat64(m.Reports.WithLabelValues("reporting_api_default", c.mode)); got != c.want {
			t.Errorf("reports_total %s = %v, want %v", c.mode, got, c.want)
		}
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("reporting_api_default", "validation_error")); got != 1 {
		t.Errorf("reports_errors_total validation_error = %v, want 1", got)
	}
}

func TestReportAPIDefaultHandlerSetsCORSHeaderOnResponse(t *testing.T) {
	l, _ := newTestLogger()
	h := NewReportAPIDefaultHandler(false, false, false, false, l, nil)

	req := httptest.NewRequest("POST", "/reporting-api/default", strings.NewReader("[]"))
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
	}
}
