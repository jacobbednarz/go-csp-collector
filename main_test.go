package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
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

var cspViolationReportHandler = &handler.CSPViolationReportHandler{
	BlockedURIs:                 utils.DefaultIgnoredBlockedURIs,
	TruncateQueryStringFragment: false,
	Logger:                      logrus.New(),
}

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
