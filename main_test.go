package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jacobbednarz/go-csp-collector/internal/handler"
	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

var cspViolationReportHandler = handler.NewCSPHandler(false, defaultBlockedURIs, nil, false, false, false, false, slog.New(slog.DiscardHandler), nil)

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

// Browsers report a blocked URL that isn't http(s) as only its scheme (CSP3
// "strip URL for use in reports"), while Safari still sends the full URL for
// hierarchical schemes. The built-in list has to drop both forms, and must not
// catch the keywords CSP reports for actionable violations.
func TestDefaultFilterList(t *testing.T) {
	tests := []struct {
		name       string
		blockedURI string
		wantStatus int
	}{
		{"chrome_extension", "chrome-extension", http.StatusBadRequest},
		{"chrome_extension_full_url", "chrome-extension://abcdef/content.js", http.StatusBadRequest},
		{"firefox_extension", "moz-extension", http.StatusBadRequest},
		{"safari_web_extension", "safari-web-extension", http.StatusBadRequest},
		{"safari_web_extension_full_url", "safari-web-extension://ABC-123/script.js", http.StatusBadRequest},
		{"safari_legacy_extension", "safari-extension", http.StatusBadRequest},
		{"edge_legacy_extension", "ms-browser-extension", http.StatusBadRequest},
		{"firefox_legacy_jar", "jar", http.StatusBadRequest},
		{"firefox_resource", "resource", http.StatusBadRequest},
		{"maxthon_addon", "mxaddon-pkg", http.StatusBadRequest},
		{"trend_micro_toolbar", "tmtbff", http.StatusBadRequest},
		{"norton", "symres", http.StatusBadRequest},
		{"about_blank", "about", http.StatusBadRequest},
		{"about_blank_full_url", "about:blank", http.StatusBadRequest},
		{"webview_bridge", "wvjbscheme", http.StatusBadRequest},
		{"webview_bridge_full_url", "wvjbscheme://__wvjb_queue_message__", http.StatusBadRequest},
		{"baidu_adblock", "nativebaiduhd", http.StatusBadRequest},
		{"https_resource", "https://example.com/app.js", http.StatusOK},
		{"inline", "inline", http.StatusOK},
		{"eval", "eval", http.StatusOK},
		{"wasm_eval", "wasm-eval", http.StatusOK},
		{"trusted_types_sink", "trusted-types-sink", http.StatusOK},
		{"data", "data", http.StatusOK},
		{"blob", "blob", http.StatusOK},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			l := slog.New(slog.DiscardHandler)
			h := handler.NewCSPHandler(false, defaultBlockedURIs, nil, false, false, false, false, l, nil)

			body := `{"csp-report":{"document-uri":"https://example.com/","blocked-uri":"` + tt.blockedURI + `"}}`
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest("POST", "/csp", strings.NewReader(body)))

			if rr.Code != tt.wantStatus {
				t.Errorf("blocked-uri %q: got status %d, want %d", tt.blockedURI, rr.Code, tt.wantStatus)
			}
		})
	}
}

// The Helm chart can't read files outside its own directory, so it ships a
// copy of the built-in list as the example for custom.filterlist.
func TestHelmFilterListMatchesBuiltIn(t *testing.T) {
	helm, err := os.ReadFile("deployments/kubernetes-helm/configMaps/filterlist.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(helm) != defaultFilterList {
		t.Errorf("deployments/kubernetes-helm/configMaps/filterlist.txt differs from sample.filterlist.txt; copy it over")
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
	r := newRouter(routerConfig{healthCheckPath: defaultHealthCheckPath, endpoints: allEndpoints(t)}, slog.New(slog.DiscardHandler), metrics.New(prometheus.NewRegistry()))

	for _, path := range []string{"/nel", "/nel/report-only", "/reporting-api/csp", "/reporting-api/coop", "/reporting-api/coep", "/reporting-api/default"} {
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
				"Access-Control-Allow-Origin":  "*",
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
	logger := slog.New(slog.DiscardHandler)
	r := newRouter(routerConfig{healthCheckPath: defaultHealthCheckPath, endpoints: allEndpoints(t)}, logger, metrics.New(prometheus.NewRegistry()))

	for _, path := range []string{"/nel", "/nel/report-only", "/reporting-api/csp", "/reporting-api/coop", "/reporting-api/coep", "/reporting-api/default"} {
		t.Run(path, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, path, strings.NewReader("[]"))
			req.Header.Set("Origin", "https://site.example")
			req.Header.Set("Content-Type", "application/reports+json")
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, req)

			if rr.Code != http.StatusOK {
				t.Fatalf("expected 200, got %d", rr.Code)
			}
			if got := rr.Header().Get("Access-Control-Allow-Origin"); got != "*" {
				t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "*")
			}
		})
	}
}

func allEndpoints(t *testing.T) map[string]bool {
	t.Helper()
	enabled, err := parseEndpoints(strings.Join(endpointGroups, ","))
	if err != nil {
		t.Fatalf("parsing default endpoints: %v", err)
	}
	return enabled
}

func TestParseEndpoints(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    map[string]bool
		wantErr string
	}{
		{name: "all_groups", value: "csp,reporting-api-csp,nel,reporting-api-coop,reporting-api-coep,reporting-api-default", want: map[string]bool{"csp": true, "reporting-api-csp": true, "nel": true, "reporting-api-coop": true, "reporting-api-coep": true, "reporting-api-default": true}},
		{name: "single_group", value: "csp", want: map[string]bool{"csp": true}},
		{name: "surrounding_whitespace", value: " csp , nel ", want: map[string]bool{"csp": true, "nel": true}},
		{name: "duplicates_and_empty_entries", value: "nel,,nel,", want: map[string]bool{"nel": true}},
		{name: "unknown_group", value: "csp,nell", wantErr: `unknown endpoint "nell", valid endpoints are: csp, reporting-api-csp, nel, reporting-api-coop, reporting-api-coep, reporting-api-default`},
		{name: "empty", value: "", wantErr: "at least one endpoint must be enabled"},
		{name: "only_separators", value: " , ", wantErr: "at least one endpoint must be enabled"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseEndpoints(tt.value)
			if tt.wantErr != "" {
				if err == nil || err.Error() != tt.wantErr {
					t.Fatalf("error = %v, want %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseEndpoints(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

// Every route belongs to exactly one endpoint group. A disabled group's
// routes must not be registered at all, so they fall through to the 404
// handler, while the health check stays available regardless.
func TestNewRouterOnlyRegistersEnabledEndpoints(t *testing.T) {
	routes := []struct {
		group  string
		method string
		path   string
	}{
		{group: "csp", method: http.MethodPost, path: "/"},
		{group: "csp", method: http.MethodPost, path: "/csp"},
		{group: "csp", method: http.MethodPost, path: "/csp/report-only"},
		{group: "reporting-api-csp", method: http.MethodOptions, path: "/reporting-api/csp"},
		{group: "reporting-api-csp", method: http.MethodPost, path: "/reporting-api/csp"},
		{group: "nel", method: http.MethodOptions, path: "/nel"},
		{group: "nel", method: http.MethodPost, path: "/nel"},
		{group: "nel", method: http.MethodOptions, path: "/nel/report-only"},
		{group: "nel", method: http.MethodPost, path: "/nel/report-only"},
		{group: "reporting-api-coop", method: http.MethodOptions, path: "/reporting-api/coop"},
		{group: "reporting-api-coop", method: http.MethodPost, path: "/reporting-api/coop"},
		{group: "reporting-api-coep", method: http.MethodOptions, path: "/reporting-api/coep"},
		{group: "reporting-api-coep", method: http.MethodPost, path: "/reporting-api/coep"},
		{group: "reporting-api-default", method: http.MethodOptions, path: "/reporting-api/default"},
		{group: "reporting-api-default", method: http.MethodPost, path: "/reporting-api/default"},
	}

	for _, enabled := range []string{"csp", "reporting-api-csp", "nel", "csp,nel", "csp,reporting-api-csp,nel", "reporting-api-coop", "reporting-api-coep", "reporting-api-default"} {
		t.Run(enabled, func(t *testing.T) {
			endpoints, err := parseEndpoints(enabled)
			if err != nil {
				t.Fatalf("parseEndpoints(%q): %v", enabled, err)
			}
			logger := slog.New(slog.DiscardHandler)
			r := newRouter(routerConfig{healthCheckPath: defaultHealthCheckPath, endpoints: endpoints}, logger, metrics.New(prometheus.NewRegistry()))

			for _, route := range routes {
				rr := httptest.NewRecorder()
				r.ServeHTTP(rr, httptest.NewRequest(route.method, route.path, strings.NewReader("[]")))

				if gotRegistered, wantRegistered := rr.Code != http.StatusNotFound, endpoints[route.group]; gotRegistered != wantRegistered {
					t.Errorf("%s %s: registered = %v (status %d), want %v", route.method, route.path, gotRegistered, rr.Code, wantRegistered)
				}
			}

			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, defaultHealthCheckPath, nil))
			if rr.Code != http.StatusOK {
				t.Errorf("health check status = %d, want 200", rr.Code)
			}
		})
	}
}

// A known path with the wrong method is a 405 naming the allowed methods,
// not a 404, so a misconfigured client can tell the two apart. Uncleaned
// paths redirect with a 307, which keeps a POST and its body; a 301 lets a
// client retry as a GET, losing the report.
func TestNewRouterMethodAndPathHandling(t *testing.T) {
	r := newRouter(routerConfig{healthCheckPath: defaultHealthCheckPath, endpoints: allEndpoints(t)}, slog.New(slog.DiscardHandler), metrics.New(prometheus.NewRegistry()))

	tests := []struct {
		name         string
		method       string
		path         string
		wantStatus   int
		wantAllow    string
		wantLocation string
	}{
		{name: "csp_get", method: http.MethodGet, path: "/csp", wantStatus: http.StatusMethodNotAllowed, wantAllow: "POST"},
		{name: "root_get", method: http.MethodGet, path: "/", wantStatus: http.StatusMethodNotAllowed, wantAllow: "POST"},
		{name: "reporting_api_put", method: http.MethodPut, path: "/reporting-api/csp", wantStatus: http.StatusMethodNotAllowed, wantAllow: "OPTIONS, POST"},
		{name: "health_check_post", method: http.MethodPost, path: "/_healthcheck", wantStatus: http.StatusMethodNotAllowed, wantAllow: "GET, HEAD"},
		{name: "health_check_head", method: http.MethodHead, path: "/_healthcheck", wantStatus: http.StatusOK},
		{name: "unknown_path", method: http.MethodPost, path: "/nope", wantStatus: http.StatusNotFound},
		{name: "trailing_slash", method: http.MethodPost, path: "/csp/", wantStatus: http.StatusNotFound},
		{name: "unclean_path", method: http.MethodPost, path: "//csp", wantStatus: http.StatusTemporaryRedirect, wantLocation: "/csp"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			r.ServeHTTP(rr, httptest.NewRequest(tt.method, tt.path, strings.NewReader("[]")))

			got := []any{rr.Code, rr.Header().Get("Allow"), rr.Header().Get("Location")}
			want := []any{tt.wantStatus, tt.wantAllow, tt.wantLocation}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s: (status, Allow, Location) = %v, want %v", tt.method, tt.path, got, want)
			}
		})
	}
}

// Without timeouts a client can hold a connection open indefinitely by
// sending its headers or body slowly.
func TestNewServerSetsTimeouts(t *testing.T) {
	h := http.NewServeMux()
	got := newServer(h)
	want := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("newServer() = %+v, want %+v", got, want)
	}
}

// A rollout sends SIGTERM to the old pod while it may still be handling
// reports. Those requests should finish rather than be cut off.
func TestServeFinishesInFlightRequestsOnShutdown(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}

	started := make(chan struct{})
	srv := newServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(started)
		time.Sleep(100 * time.Millisecond)
		w.WriteHeader(http.StatusOK)
	}))

	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { served <- serve(ctx, srv, ln) }()

	status := make(chan int, 1)
	go func() {
		r, err := http.Post("http://"+ln.Addr().String(), "application/json", nil)
		if err != nil {
			t.Errorf("in-flight request failed: %v", err)
			status <- 0
			return
		}
		r.Body.Close()
		status <- r.StatusCode
	}()

	<-started
	cancel()

	if got := <-status; got != http.StatusOK {
		t.Errorf("in-flight request got %d, want 200", got)
	}
	if err := <-served; err != nil {
		t.Errorf("serve() = %v, want nil after a clean shutdown", err)
	}
	if r, err := http.Post("http://"+ln.Addr().String(), "application/json", nil); err == nil {
		r.Body.Close()
		t.Error("expected new connections to be refused after shutdown")
	}
}

func TestServeReturnsListenerErrors(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()

	if err := serve(context.Background(), newServer(http.NewServeMux()), ln); err == nil {
		t.Error("serve() = nil, want the error from a closed listener")
	}
}

// Log pipelines parse the collector's output, so the keys and level names
// stay the ones it has always written: timestamp, level and message, with
// logrus' lowercase level names and RFC 3339 timestamps. Text output leaves
// out a report's empty message, while JSON has always kept it.
func TestNewLogHandlerKeepsTheLogFormat(t *testing.T) {
	timestamp := regexp.MustCompile(`\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})`)
	tests := []struct {
		format string
		want   string
	}{
		{
			format: "text",
			want: `timestamp=TS level=info blocked_uri=inline document_uri="https://example.com/a b" metadata=<nil> report_only=false
timestamp=TS level=warning message="unable to parse client ip" error=bad
`,
		},
		{
			format: "json",
			want: `{"timestamp":"TS","level":"info","message":"","blocked_uri":"inline","document_uri":"https://example.com/a b","metadata":null,"report_only":false}
{"timestamp":"TS","level":"warning","message":"unable to parse client ip","error":"bad"}
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.format, func(t *testing.T) {
			var buf bytes.Buffer
			l := slog.New(newLogHandler(&buf, tt.format, slog.LevelInfo))
			l.Info("", "blocked_uri", "inline", "document_uri", "https://example.com/a b", "metadata", nil, "report_only", false)
			l.Warn("unable to parse client ip", "error", "bad")
			l.Debug("hidden below the configured level")

			if got := timestamp.ReplaceAllString(buf.String(), "TS"); got != tt.want {
				t.Errorf("output =\n%s\nwant\n%s", got, tt.want)
			}
		})
	}
}
