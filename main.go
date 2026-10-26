package main

import (
	_ "embed"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/handler"
	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"

	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/sirupsen/logrus"
)

const (
	// Default health check url.
	defaultHealthCheckPath = "/_healthcheck"
)

var (
	// Rev is set at build time and holds the revision that the package
	// was created at.
	Rev = "dev"

	// Shared defaults for the logger output. This ensures that we are
	// using the same keys for the `FieldKey` values across both formatters.
	logFieldMapDefaults = logrus.FieldMap{
		logrus.FieldKeyTime:  "timestamp",
		logrus.FieldKeyLevel: "level",
		logrus.FieldKeyMsg:   "message",
	}

	// defaultFilterList is the built-in blocked URI filter list. It's
	// embedded from the sample file so that the file people copy for
	// --filter-file is always the list the collector actually uses.
	//
	//go:embed sample.filterlist.txt
	defaultFilterList string

	defaultBlockedURIs = utils.TrimEmptyAndComments(strings.Split(defaultFilterList, "\n"))
)

var logger = logrus.New()

func init() {
	logger.SetOutput(os.Stdout)
	logger.SetLevel(logrus.InfoLevel)
}

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

	if *debugFlag {
		logger.SetLevel(logrus.DebugLevel)
	}

	if *outputFormat == "json" {
		logger.SetFormatter(&logrus.JSONFormatter{
			FieldMap: logFieldMapDefaults,
		})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{
			FullTimestamp:          true,
			DisableLevelTruncation: true,
			QuoteEmptyFields:       true,
			DisableColors:          true,
			FieldMap:               logFieldMapDefaults,
		})
	}

	logger.Debug("starting up...")
	ignoredBlockedURIs := defaultBlockedURIs
	if *blockedURIFile != "" {
		logger.Debugf("using Filter list from file at: %s\n", *blockedURIFile)

		content, err := os.ReadFile(*blockedURIFile)
		if err != nil {
			logrus.Fatalf("error reading Blocked File list: %s", *blockedURIFile)
		}
		ignoredBlockedURIs = utils.TrimEmptyAndComments(strings.Split(string(content), "\n"))
	} else {
		logger.Debug("using filter list from internal list")
	}

	var blockedDomains []string
	if *blockedDomainFile != "" {
		logger.Debugf("using domain filter list from file at: %s\n", *blockedDomainFile)

		content, err := os.ReadFile(*blockedDomainFile)
		if err != nil {
			logrus.Fatalf("error reading blocked domain file: %s", *blockedDomainFile)
		}
		blockedDomains = utils.TrimEmptyAndComments(strings.Split(string(content), "\n"))
	}

	enabledEndpoints, err := parseEndpoints(*endpoints)
	if err != nil {
		logrus.Fatalf("invalid --endpoints value: %s", err)
	}

	registry := prometheus.NewRegistry()
	m := metrics.New(registry)
	r := newRouter(routerConfig{
		healthCheckPath:             *healthCheckPath,
		blockedURIs:                 ignoredBlockedURIs,
		blockedDomains:              blockedDomains,
		truncateQueryStringFragment: *truncateQueryStringFragment,
		logClientIP:                 *logClientIP,
		logTruncatedClientIP:        *logTruncatedClientIP,
		metadataObject:              *metadataObject,
		endpoints:                   enabledEndpoints,
	}, logger, m)

	logger.Debugf("blocked URI list: %s", ignoredBlockedURIs)
	logger.Debugf("blocked domain list: %s", blockedDomains)
	logger.Debugf("enabled endpoints: %s", *endpoints)
	logger.Debugf("listening on TCP port: %s", strconv.Itoa(*listenPort))
	logger.Debugf("metrics endpoint listening on %s:%d", *metricsBindAddr, *metricsPort)

	go func() {
		metricsMux := http.NewServeMux()
		metricsMux.Handle("/metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{}))
		metricsAddress := fmt.Sprintf("%s:%d", *metricsBindAddr, *metricsPort)
		logger.Fatal(http.ListenAndServe(metricsAddress, metricsMux))
	}()

	logger.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", strconv.Itoa(*listenPort)), r))
}

// routerConfig holds the flag values that shape how reports are handled.
type routerConfig struct {
	healthCheckPath             string
	blockedURIs                 []string
	blockedDomains              []string
	truncateQueryStringFragment bool
	logClientIP                 bool
	logTruncatedClientIP        bool
	metadataObject              bool
	endpoints                   map[string]bool
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
func newRouter(cfg routerConfig, logger *logrus.Logger, m *metrics.Metrics) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc(cfg.healthCheckPath, handler.HealthcheckHandler).Methods("GET")

	wrapWithPrometheus := func(handlerName string, route string, h http.Handler) http.Handler {
		labels := prometheus.Labels{"handler": handlerName, "route": route}
		return promhttp.InstrumentHandlerDuration(
			m.RequestDuration.MustCurryWith(labels),
			promhttp.InstrumentHandlerInFlight(m.RequestsInFlight.With(labels), h),
		)
	}

	if cfg.endpoints["csp"] {
		r.Handle("/csp/report-only", wrapWithPrometheus("csp", "/csp/report-only", handler.NewCSPHandler(
			true, cfg.blockedURIs, cfg.blockedDomains, cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")

		r.Handle("/csp", wrapWithPrometheus("csp", "/csp", handler.NewCSPHandler(
			false, cfg.blockedURIs, cfg.blockedDomains, cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")

		r.Handle("/", wrapWithPrometheus("csp", "/", handler.NewCSPHandler(
			false, cfg.blockedURIs, cfg.blockedDomains, cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")
	}

	if cfg.endpoints["reporting-api-csp"] {
		r.HandleFunc("/reporting-api/csp", handler.ReportAPICorsHandler).Methods("OPTIONS")
		r.Handle("/reporting-api/csp", wrapWithPrometheus("reporting_api_csp", "/reporting-api/csp", handler.NewReportAPICSPHandler(
			cfg.blockedURIs, cfg.blockedDomains, cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")
	}

	if cfg.endpoints["nel"] {
		r.HandleFunc("/nel/report-only", handler.ReportAPICorsHandler).Methods("OPTIONS")
		r.Handle("/nel/report-only", wrapWithPrometheus("nel", "/nel/report-only", handler.NewNELHandler(
			true, cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")

		r.HandleFunc("/nel", handler.ReportAPICorsHandler).Methods("OPTIONS")
		r.Handle("/nel", wrapWithPrometheus("nel", "/nel", handler.NewNELHandler(
			false, cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")
	}

	if cfg.endpoints["reporting-api-coop"] {
		r.HandleFunc("/reporting-api/coop", handler.ReportAPICorsHandler).Methods("OPTIONS")
		r.Handle("/reporting-api/coop", wrapWithPrometheus("reporting_api_coop", "/reporting-api/coop", handler.NewReportAPICOOPHandler(
			cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")
	}

	if cfg.endpoints["reporting-api-coep"] {
		r.HandleFunc("/reporting-api/coep", handler.ReportAPICorsHandler).Methods("OPTIONS")
		r.Handle("/reporting-api/coep", wrapWithPrometheus("reporting_api_coep", "/reporting-api/coep", handler.NewReportAPICOEPHandler(
			cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")
	}

	if cfg.endpoints["reporting-api-default"] {
		r.HandleFunc("/reporting-api/default", handler.ReportAPICorsHandler).Methods("OPTIONS")
		r.Handle("/reporting-api/default", wrapWithPrometheus("reporting_api_default", "/reporting-api/default", handler.NewReportAPIDefaultHandler(
			cfg.truncateQueryStringFragment, cfg.logClientIP, cfg.logTruncatedClientIP, cfg.metadataObject, logger, m,
		))).Methods("POST")
	}

	r.NotFoundHandler = r.NewRoute().HandlerFunc(http.NotFound).GetHandler()

	return r
}
