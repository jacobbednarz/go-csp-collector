package handler

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
	logtest "github.com/sirupsen/logrus/hooks/test"
)

func TestReportAPICOEPHandlerLogsReport(t *testing.T) {
	tests := []struct {
		name     string
		truncate bool
		body     string
		want     logrus.Fields
	}{
		{
			name: "corp_enforced",
			body: `[{"type":"coep","url":"https://example.com/page?q=1","age":10,"user_agent":"t","body":{
				"type":"corp","blockedURL":"https://cdn.example/img.png?v=1","destination":"image","disposition":"enforce"}}]`,
			want: logrus.Fields{
				"report_only": false,
				"url":         "https://example.com/page?q=1",
				"type":        "corp",
				"blocked_uri": "https://cdn.example/img.png?v=1",
				"destination": "image",
				"disposition": "enforce",
				"metadata":    nil,
				"path":        "/reporting-api/coep",
			},
		},
		{
			name: "navigation_report_only",
			body: `[{"type":"coep","url":"https://example.com/","body":{
				"type":"navigation","blockedURL":"https://frame.example/","disposition":"reporting"}}]`,
			want: logrus.Fields{
				"report_only": true,
				"url":         "https://example.com/",
				"type":        "navigation",
				"blocked_uri": "https://frame.example/",
				"destination": "",
				"disposition": "reporting",
				"metadata":    nil,
				"path":        "/reporting-api/coep",
			},
		},
		{
			name:     "truncates_url_fields",
			truncate: true,
			body: `[{"type":"coep","url":"https://example.com/page?q=1#f","body":{
				"type":"corp","blockedURL":"https://cdn.example/img.png?v=1","destination":"image","disposition":"enforce"}}]`,
			want: logrus.Fields{
				"report_only": false,
				"url":         "https://example.com/page",
				"type":        "corp",
				"blocked_uri": "https://cdn.example/img.png",
				"destination": "image",
				"disposition": "enforce",
				"metadata":    nil,
				"path":        "/reporting-api/coep",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, _ := newTestLogger()
			hook := logtest.NewLocal(l)
			h := NewReportAPICOEPHandler(tt.truncate, false, false, false, l, nil)

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/coep", strings.NewReader(tt.body)))

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
			entries := hook.AllEntries()
			if len(entries) != 1 {
				t.Fatalf("got %d log entries, want 1", len(entries))
			}
			if !reflect.DeepEqual(entries[0].Data, tt.want) {
				t.Errorf("log fields = %v, want %v", entries[0].Data, tt.want)
			}
		})
	}
}

func TestReportAPICOEPHandlerMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := NewReportAPICOEPHandler(false, false, false, false, l, m)

	body := `[
		{"type":"coep","url":"https://example.com/","body":{"type":"corp","disposition":"enforce"}},
		{"type":"coep","url":"https://example.com/","body":{"type":"corp","disposition":"reporting"}},
		{"type":"coep","url":"about:blank","body":{"type":"corp","disposition":"enforce"}},
		{"type":"coop","url":"https://example.com/","body":{"type":"navigation-from-response","disposition":"enforce"}}
	]`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/coep", strings.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	for _, c := range []struct {
		name string
		got  float64
		want float64
	}{
		{"reports_total enforced", testutil.ToFloat64(m.Reports.WithLabelValues("reporting_api_coep", "enforced")), 1},
		{"reports_total report_only", testutil.ToFloat64(m.Reports.WithLabelValues("reporting_api_coep", "report_only")), 1},
		{"reports_errors_total validation_error", testutil.ToFloat64(m.ReportErrors.WithLabelValues("reporting_api_coep", "validation_error")), 1},
		{"reports_ignored_total unsupported_type", testutil.ToFloat64(m.ReportIgnored.WithLabelValues("reporting_api_coep", "unsupported_type")), 1},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestReportAPICOEPHandlerSetsCORSHeaderOnResponse(t *testing.T) {
	l, _ := newTestLogger()
	h := NewReportAPICOEPHandler(false, false, false, false, l, nil)

	req := httptest.NewRequest("POST", "/reporting-api/coep", strings.NewReader("[]"))
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://example.com")
	}
}
