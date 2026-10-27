package main

import (
	"context"
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/jacobbednarz/go-csp-collector/internal/handler"
	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

const (
	// Default health check url.
	defaultHealthCheckPath = "/_healthcheck"
)

var (
	// Rev is set at build time and holds the revision that the package
	// was created at.
	Rev = "dev"

	// defaultFilterList is the built-in blocked URI filter list. It's
	// embedded from the sample file so that the file people copy for
	// --filter-file is always the list the collector actually uses.
	//
	//go:embed sample.filterlist.txt
	defaultFilterList string

	defaultBlockedURIs = utils.ParseFilterList(defaultFilterList)
)

func main() {
	version := flag.Bool("version", false, "Display the version")
	debugFlag := flag.Bool("debug", false, "Output additional logging for debugging")
	outputFormat := flag.String("output-format", "text", "Define how the violation reports are formatted for output.\nDefaults to 'text'. Valid options are 'text' or 'json'")
	blockedURIFile := flag.String("filter-file", "", "Blocked URI filter file (one prefix per line)")
	blockedDomainFile := flag.String("filter-domains-file", "", "Blocked domain filter file (one domain per line; blocks exact matches and all subdomains)")
	listenPort := flag.Int("port", 8080, "Port to listen on")
	metricsPort := flag.Int("metrics-port", 9090, "Port for the Prometheus metrics endpoint")
	metricsBindAddr := flag.String("metrics-bind-addr", "127.0.0.1", "Bind address for the Prometheus metrics endpoint")
	healthCheckPath := flag.String("health-check-path", defaultHealthCheckPath, "Health checker path")
	truncateQueryStringFragment := flag.Bool("truncate-query-fragment", false, "Truncate query string and fragment from document-uri, referrer and blocked-uri before logging (to reduce chances of accidentally logging sensitive data)")

	logClientIP := flag.Bool("log-client-ip", false, "Log the reporting client IP address")
	logTruncatedClientIP := flag.Bool("log-truncated-client-ip", false, "Log the truncated client IP address (IPv4: /24, IPv6: /64")

	metadataObject := flag.Bool("query-params-metadata", false, "Write query parameters of the report URI as JSON object under metadata instead of the single metadata string")

	endpoints := flag.String("endpoints", strings.Join(endpointGroups, ","), "Comma separated list of endpoint groups to serve: "+strings.Join(endpointGroups, ", "))

	flag.Parse()

	if *version {
		fmt.Printf("csp-collector (%s)\n", Rev)
		os.Exit(0)
	}

	level := slog.LevelInfo
	if *debugFlag {
		level = slog.LevelDebug
	}
	logger := slog.New(newLogHandler(os.Stdout, *outputFormat, level))

	// Errors go to stderr so they stay visible when stdout, the reports,
	// is redirected to a file.
	errLogger := slog.New(newLogHandler(os.Stderr, *outputFormat, level))
	fatal := func(msg string, args ...any) {
		errLogger.Error(msg, args...)
		os.Exit(1)
	}

	// Flag parsing stops at the first argument that isn't a flag, so
	// anything after it would be silently ignored. The image's entrypoint
	// is the binary, so an old `/csp_collector --flag` command lands here.
	if flag.NArg() > 0 {
		fatal("unexpected argument, only flags are accepted", "argument", flag.Arg(0))
	}

	// Both write the same client_ip field, so one would silently win.
	if *logClientIP && *logTruncatedClientIP {
		fatal("--log-client-ip and --log-truncated-client-ip can't be combined, pick one")
	}

	logger.Debug("starting up")
	ignoredBlockedURIs := defaultBlockedURIs
	if *blockedURIFile != "" {
		logger.Debug("using filter list from file", "path", *blockedURIFile)

		content, err := os.ReadFile(*blockedURIFile)
		if err != nil {
			fatal("unable to read filter list", "path", *blockedURIFile, "error", err)
		}
		ignoredBlockedURIs = utils.ParseFilterList(string(content))
	} else {
		logger.Debug("using the built-in filter list")
	}

	var blockedDomains []string
	if *blockedDomainFile != "" {
		logger.Debug("using domain filter list from file", "path", *blockedDomainFile)

		content, err := os.ReadFile(*blockedDomainFile)
		if err != nil {
			fatal("unable to read domain filter list", "path", *blockedDomainFile, "error", err)
		}
		blockedDomains = utils.ParseFilterList(string(content))
	}

	// The path becomes part of a ServeMux pattern, where braces are
	// wildcards and a missing leading slash is a panic.
	if !strings.HasPrefix(*healthCheckPath, "/") || strings.ContainsAny(*healthCheckPath, "{} \t") {
		fatal("invalid --health-check-path, it must start with / and can't contain spaces or braces", "path", *healthCheckPath)
	}

	enabledEndpoints, err := parseEndpoints(*endpoints)
	if err != nil {
		fatal("invalid --endpoints value", "error", err)
	}

	clientIP := handler.ClientIPNone
	switch {
	case *logClientIP:
		clientIP = handler.ClientIPFull
	case *logTruncatedClientIP:
		clientIP = handler.ClientIPTruncated
	}

	registry := prometheus.NewRegistry()
	r := newRouter(routerConfig{
		healthCheckPath: *healthCheckPath,
		filter:          handler.Filter{BlockedURIs: ignoredBlockedURIs, BlockedDomains: blockedDomains},
		endpoints:       enabledEndpoints,
		handler: handler.Options{
			TruncateQueryStringFragment: *truncateQueryStringFragment,
			ClientIP:                    clientIP,
			MetadataObject:              *metadataObject,
			Logger:                      logger,
			Metrics:                     metrics.New(registry),
		},
	})

	logger.Debug("configured",
		"blocked_uris", ignoredBlockedURIs,
		"blocked_domains", blockedDomains,
		"endpoints", *endpoints,
		"port", *listenPort,
		"metrics_addr", fmt.Sprintf("%s:%d", *metricsBindAddr, *metricsPort),
	)

	// Bind both listeners up front so a port that's already in use fails
	// at startup instead of from inside a goroutine.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", *listenPort))
	if err != nil {
		fatal("unable to listen for reports", "error", err)
	}
	metricsLn, err := net.Listen("tcp", fmt.Sprintf("%s:%d", *metricsBindAddr, *metricsPort))
	if err != nil {
		fatal("unable to listen for metrics", "error", err)
	}

	metricsMux := http.NewServeMux()
	metricsMux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errs := make(chan error, 2)
	go func() { errs <- serve(ctx, newServer(metricsMux), metricsLn) }()
	go func() { errs <- serve(ctx, newServer(r), ln) }()

	// Either server failing stops the other, so the process exits rather
	// than carrying on with only one of its listeners.
	failed := false
	for range 2 {
		if err := <-errs; err != nil {
			errLogger.Error("server stopped", "error", err)
			failed = true
			stop()
		}
	}
	if failed {
		os.Exit(1)
	}
}

// newLogHandler writes logs in the given format with the timestamp, level
// and message keys the collector has always used, so existing log parsers
// keep working.
func newLogHandler(w io.Writer, format string, level slog.Leveler) slog.Handler {
	json := format == "json"
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(groups []string, a slog.Attr) slog.Attr {
			if len(groups) > 0 {
				return a
			}

			switch a.Key {
			case slog.TimeKey:
				return slog.String("timestamp", a.Value.Time().Format(time.RFC3339))
			case slog.LevelKey:
				if a.Value.Any() == slog.LevelWarn {
					return slog.String("level", "warning")
				}
				return slog.String("level", strings.ToLower(a.Value.String()))
			case slog.MessageKey:
				// Report lines have no message. Text output has always
				// left the empty key out, while JSON has always kept it.
				if !json && a.Value.String() == "" {
					return slog.Attr{}
				}
				return slog.String("message", a.Value.String())
			}
			return a
		},
	}

	if json {
		return slog.NewJSONHandler(w, opts)
	}
	return slog.NewTextHandler(w, opts)
}

// shutdownTimeout is how long in-flight requests get to finish after a
// SIGTERM. It's well inside Kubernetes' default 30 second grace period.
const shutdownTimeout = 10 * time.Second

// newServer sets timeouts so a slow client can't hold a connection open
// indefinitely. ReadTimeout leaves room for a full size batch on a slow
// mobile connection.
func newServer(h http.Handler) *http.Server {
	return &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       2 * time.Minute,
	}
}

// serve runs srv on ln until ctx is cancelled, then shuts it down, giving
// in-flight requests up to shutdownTimeout to finish.
func serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	errs := make(chan error, 1)
	go func() { errs <- srv.Serve(ln) }()

	select {
	case err := <-errs:
		return err
	case <-ctx.Done():
	}

	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

// routerConfig holds the flag values that shape how reports are handled.
type routerConfig struct {
	healthCheckPath string
	filter          handler.Filter
	endpoints       map[string]bool
	handler         handler.Options
}

// endpointGroups are the names accepted by --endpoints. Each one enables
// every route, including CORS preflights, for one kind of report.
var endpointGroups = []string{"csp", "reporting-api-csp", "nel", "reporting-api-coop", "reporting-api-coep", "reporting-api-default"}

// parseEndpoints turns the comma separated --endpoints value into the set
// of enabled groups. An unknown name is an error rather than ignored, so a
// typo can't silently turn an endpoint off.
func parseEndpoints(value string) (map[string]bool, error) {
	enabled := make(map[string]bool)
	for _, name := range strings.Split(value, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		if !slices.Contains(endpointGroups, name) {
			return nil, fmt.Errorf("unknown endpoint %q, valid endpoints are: %s", name, strings.Join(endpointGroups, ", "))
		}
		enabled[name] = true
	}
	if len(enabled) == 0 {
		return nil, errors.New("at least one endpoint must be enabled")
	}
	return enabled, nil
}

// newRouter registers the report endpoints for each enabled group, kept
// out of main so the route table itself can be tested.
func newRouter(cfg routerConfig) *http.ServeMux {
	r := http.NewServeMux()
	r.HandleFunc("GET "+cfg.healthCheckPath, handler.HealthcheckHandler)

	wrapWithPrometheus := func(handlerName string, route string, h http.Handler) http.Handler {
		labels := prometheus.Labels{"handler": handlerName, "route": route}
		return promhttp.InstrumentHandlerDuration(
			cfg.handler.Metrics.RequestDuration.MustCurryWith(labels),
			promhttp.InstrumentHandlerInFlight(cfg.handler.Metrics.RequestsInFlight.With(labels), h),
		)
	}

	if cfg.endpoints["csp"] {
		r.Handle("POST /csp/report-only", wrapWithPrometheus("csp", "/csp/report-only", handler.NewCSPHandler(true, cfg.filter, cfg.handler)))

		r.Handle("POST /csp", wrapWithPrometheus("csp", "/csp", handler.NewCSPHandler(false, cfg.filter, cfg.handler)))

		r.Handle("POST /{$}", wrapWithPrometheus("csp", "/", handler.NewCSPHandler(false, cfg.filter, cfg.handler)))
	}

	if cfg.endpoints["reporting-api-csp"] {
		r.HandleFunc("OPTIONS /reporting-api/csp", handler.ReportAPICorsHandler)
		r.Handle("POST /reporting-api/csp", wrapWithPrometheus("reporting_api_csp", "/reporting-api/csp", handler.NewReportAPICSPHandler(cfg.filter, cfg.handler)))
	}

	if cfg.endpoints["nel"] {
		r.HandleFunc("OPTIONS /nel/report-only", handler.ReportAPICorsHandler)
		r.Handle("POST /nel/report-only", wrapWithPrometheus("nel", "/nel/report-only", handler.NewNELHandler(true, cfg.handler)))

		r.HandleFunc("OPTIONS /nel", handler.ReportAPICorsHandler)
		r.Handle("POST /nel", wrapWithPrometheus("nel", "/nel", handler.NewNELHandler(false, cfg.handler)))
	}

	if cfg.endpoints["reporting-api-coop"] {
		r.HandleFunc("OPTIONS /reporting-api/coop", handler.ReportAPICorsHandler)
		r.Handle("POST /reporting-api/coop", wrapWithPrometheus("reporting_api_coop", "/reporting-api/coop", handler.NewReportAPICOOPHandler(cfg.handler)))
	}

	if cfg.endpoints["reporting-api-coep"] {
		r.HandleFunc("OPTIONS /reporting-api/coep", handler.ReportAPICorsHandler)
		r.Handle("POST /reporting-api/coep", wrapWithPrometheus("reporting_api_coep", "/reporting-api/coep", handler.NewReportAPICOEPHandler(cfg.handler)))
	}

	if cfg.endpoints["reporting-api-default"] {
		r.HandleFunc("OPTIONS /reporting-api/default", handler.ReportAPICorsHandler)
		r.Handle("POST /reporting-api/default", wrapWithPrometheus("reporting_api_default", "/reporting-api/default", handler.NewReportAPIDefaultHandler(cfg.handler)))
	}

	return r
}
