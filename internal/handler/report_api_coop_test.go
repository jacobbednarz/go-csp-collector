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

func TestReportAPICOOPHandlerLogsReport(t *testing.T) {
	tests := []struct {
		name     string
		truncate bool
		body     string
		want     logrus.Fields
	}{
		{
			name: "navigation_to_response",
			body: `[{"type":"coop","url":"https://example.com/page?q=1","age":10,"user_agent":"t","body":{
				"disposition":"enforce","effectivePolicy":"same-origin","type":"navigation-to-response",
				"previousResponseURL":"https://other.example/prev?token=abc","referrer":"https://other.example/ref"}}]`,
			want: logrus.Fields{
				"report_only":               false,
				"url":                       "https://example.com/page?q=1",
				"type":                      "navigation-to-response",
				"disposition":               "enforce",
				"effective_policy":          "same-origin",
				"previous_response_url":     "https://other.example/prev?token=abc",
				"next_response_url":         "",
				"referrer":                  "https://other.example/ref",
				"property":                  "",
				"opener_url":                "",
				"opened_window_url":         "",
				"opened_window_initial_url": "",
				"other_url":                 "",
				"source_file":               "",
				"line_number":               0,
				"column_number":             0,
				"metadata":                  nil,
				"path":                      "/reporting-api/coop",
			},
		},
		{
			name: "access_to_opener",
			body: `[{"type":"coop","url":"https://example.com/popup","body":{
				"disposition":"reporting","effectivePolicy":"same-origin-allow-popups","type":"access-to-opener",
				"property":"postMessage","openedWindowURL":"https://other.example/win","openedWindowInitialURL":"https://other.example/init",
				"otherURL":"https://third.example/","sourceFile":"https://example.com/app.js","lineNumber":12,"columnNumber":4}}]`,
			want: logrus.Fields{
				"report_only":               true,
				"url":                       "https://example.com/popup",
				"type":                      "access-to-opener",
				"disposition":               "reporting",
				"effective_policy":          "same-origin-allow-popups",
				"previous_response_url":     "",
				"next_response_url":         "",
				"referrer":                  "",
				"property":                  "postMessage",
				"opener_url":                "",
				"opened_window_url":         "https://other.example/win",
				"opened_window_initial_url": "https://other.example/init",
				"other_url":                 "https://third.example/",
				"source_file":               "https://example.com/app.js",
				"line_number":               12,
				"column_number":             4,
				"metadata":                  nil,
				"path":                      "/reporting-api/coop",
			},
		},
		{
			name:     "truncates_every_url_field",
			truncate: true,
			body: `[{"type":"coop","url":"https://example.com/page?q=1#f","body":{
				"disposition":"enforce","effectivePolicy":"same-origin","type":"access-to-opener",
				"previousResponseURL":"https://a.example/p?x=1","nextResponseURL":"https://a.example/n?x=1",
				"referrer":"https://a.example/r?x=1","openerURL":"https://a.example/o?x=1",
				"openedWindowURL":"https://a.example/w?x=1","openedWindowInitialURL":"https://a.example/i?x=1",
				"otherURL":"https://a.example/other?x=1","sourceFile":"https://a.example/app.js?v=2"}}]`,
			want: logrus.Fields{
				"report_only":               false,
				"url":                       "https://example.com/page",
				"type":                      "access-to-opener",
				"disposition":               "enforce",
				"effective_policy":          "same-origin",
				"previous_response_url":     "https://a.example/p",
				"next_response_url":         "https://a.example/n",
				"referrer":                  "https://a.example/r",
				"property":                  "",
				"opener_url":                "https://a.example/o",
				"opened_window_url":         "https://a.example/w",
				"opened_window_initial_url": "https://a.example/i",
				"other_url":                 "https://a.example/other",
				"source_file":               "https://a.example/app.js",
				"line_number":               0,
				"column_number":             0,
				"metadata":                  nil,
				"path":                      "/reporting-api/coop",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l, _ := newTestLogger()
			hook := logtest.NewLocal(l)
			h := NewReportAPICOOPHandler(tt.truncate, false, false, false, l, nil)

			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/coop", strings.NewReader(tt.body)))

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

// One batch can carry several report types, and COOP's disposition is
// "enforce" or "reporting" (not CSP's "report"). Reports with an invalid
// URL are skipped without costing the rest of the batch.
func TestReportAPICOOPHandlerMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	l, _ := newTestLogger()
	h := NewReportAPICOOPHandler(false, false, false, false, l, m)

	body := `[
		{"type":"coop","url":"https://example.com/","body":{"disposition":"enforce","type":"navigation-from-response"}},
		{"type":"coop","url":"https://example.com/","body":{"disposition":"reporting","type":"navigation-from-response"}},
		{"type":"coop","url":"about:blank","body":{"disposition":"enforce","type":"navigation-from-response"}},
		{"type":"coep","url":"https://example.com/","body":{"disposition":"enforce","type":"corp"}}
	]`
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/coop", strings.NewReader(body)))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	for _, c := range []struct {
		name string
		got  float64
		want float64
	}{
		{"reports_total enforced", testutil.ToFloat64(m.Reports.WithLabelValues("reporting_api_coop", "enforced")), 1},
		{"reports_total report_only", testutil.ToFloat64(m.Reports.WithLabelValues("reporting_api_coop", "report_only")), 1},
		{"reports_errors_total validation_error", testutil.ToFloat64(m.ReportErrors.WithLabelValues("reporting_api_coop", "validation_error")), 1},
		{"reports_ignored_total unsupported_type", testutil.ToFloat64(m.ReportIgnored.WithLabelValues("reporting_api_coop", "unsupported_type")), 1},
	} {
		if c.got != c.want {
			t.Errorf("%s = %v, want %v", c.name, c.got, c.want)
		}
	}
}

func TestReportAPICOOPHandlerSetsCORSHeaderOnResponse(t *testing.T) {
	l, _ := newTestLogger()
	h := NewReportAPICOOPHandler(false, false, false, false, l, nil)

	req := httptest.NewRequest("POST", "/reporting-api/coop", strings.NewReader("[]"))
	req.Header.Set("Origin", "https://example.com")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)

	if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://example.com" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://example.com")
	}
}
