package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jacobbednarz/go-csp-collector/internal/handler"
	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/sirupsen/logrus"
)

var cspViolationReportHandler = handler.NewCSPHandler(false, utils.DefaultIgnoredBlockedURIs, nil, false, false, false, false, logrus.New(), nil)

func TestHandlerForDisallowedMethods(t *testing.T) {
	disallowedMethods := []string{"GET", "DELETE", "PUT", "TRACE", "PATCH"}
	randomUrls := []string{"/", "/blah"}

	for _, method := range disallowedMethods {
		for _, url := range randomUrls {
			t.Run(method+url, func(t *testing.T) {
				request, err := http.NewRequest(method, url, nil)
				if err != nil {
					t.Fatalf("failed to create request: %v", err)
				}
				recorder := httptest.NewRecorder()

				cspViolationReportHandler.ServeHTTP(recorder, request)

				response := recorder.Result()
				defer response.Body.Close()

				if response.StatusCode != http.StatusMethodNotAllowed {
					t.Errorf("expected HTTP status %v; got %v", http.StatusMethodNotAllowed, response.StatusCode)
				}
			})
		}
	}
}

func TestPrometheusMiddlewareLabelsAndInFlight(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	wrapped := promhttp.InstrumentHandlerDuration(
		m.RequestDuration.MustCurryWith(prometheus.Labels{"handler": "csp", "route": "/csp"}),
		promhttp.InstrumentHandlerInFlight(
			m.RequestsInFlight.With(prometheus.Labels{"handler": "csp", "route": "/csp"}),
			http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				time.Sleep(5 * time.Millisecond)
				w.WriteHeader(http.StatusCreated)
			}),
		),
	)

	req := httptest.NewRequest("POST", "/csp", bytes.NewBufferString("{}"))
	rr := httptest.NewRecorder()
	wrapped.ServeHTTP(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}

	if got := testutil.ToFloat64(m.RequestsInFlight.WithLabelValues("csp", "/csp")); got != 0 {
		t.Fatalf("in-flight gauge should return to 0, got %v", got)
	}

	metricFamilies, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed gathering metrics: %v", err)
	}

	found := false
	for _, mf := range metricFamilies {
		if mf.GetName() != "csp_collector_http_request_duration_seconds" {
			continue
		}
		for _, metric := range mf.GetMetric() {
			labels := map[string]string{}
			for _, label := range metric.GetLabel() {
				labels[label.GetName()] = label.GetValue()
			}
			if labels["handler"] == "csp" && labels["route"] == "/csp" && labels["method"] == "post" && labels["code"] == "201" {
				found = true
				break
			}
		}
	}
	if !found {
		t.Fatal("expected duration sample with handler=csp route=/csp method=post code=201")
	}
}

func TestMetricsEndpointUsesCustomRegistry(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	m.Reports.WithLabelValues("csp", "enforced").Inc()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rr := httptest.NewRecorder()
	promhttp.HandlerFor(registry, promhttp.HandlerOpts{}).ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}

	body := rr.Body.String()
	for _, needle := range []string{
		"csp_collector_reports_total",
		"go_gc_duration_seconds",
		"process_start_time_seconds",
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("expected metrics output to include %q", needle)
		}
	}
}

// Reporting API uploads use the non-safelisted application/reports+json
// content type, so a cross-origin endpoint is preflighted first. This
// mirrors Chromium's ReportingUploader, which requires a 2xx response with
// Access-Control-Allow-Origin and Access-Control-Allow-Headers covering
// content-type, and otherwise drops the batch and backs off the endpoint.
func TestReportingAPIRoutesAnswerCORSPreflight(t *testing.T) {
	r := newRouter(routerConfig{healthCheckPath: defaultHealthCheckPath}, logrus.New(), metrics.New(prometheus.NewRegistry()))

	for _, path := range []string{"/nel", "/nel/report-only", "/reporting-api/csp"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodOptions, path, nil)
			req.Header.Set("Origin", "https://site.example")
			req.Header.Set("Access-Control-Request-Method", "POST")
			req.Header.Set("Access-Control-Request-Headers", "content-type")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
			got := map[string]string{
				"Access-Control-Allow-Origin":  rr.Header().Get("Access-Control-Allow-Origin"),
				"Access-Control-Allow-Methods": rr.Header().Get("Access-Control-Allow-Methods"),
				"Access-Control-Allow-Headers": rr.Header().Get("Access-Control-Allow-Headers"),
			}
			want := map[string]string{
				"Access-Control-Allow-Origin":  "https://site.example",
				"Access-Control-Allow-Methods": "POST",
				"Access-Control-Allow-Headers": "content-type",
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("preflight headers = %v, want %v", got, want)
			}
		})
	}
}

// The upload itself must carry the CORS headers too: Fetch-based Reporting
// implementations apply the CORS check to the actual response.
func TestReportingAPIRoutesSetCORSHeadersOnUpload(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})
	r := newRouter(routerConfig{healthCheckPath: defaultHealthCheckPath}, logger, metrics.New(prometheus.NewRegistry()))

	for _, path := range []string{"/nel", "/nel/report-only", "/reporting-api/csp"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("[]"))
			req.Header.Set("Origin", "https://site.example")
			req.Header.Set("Content-Type", "application/reports+json")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "https://site.example" {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "https://site.example")
			}
		})
	}
}
