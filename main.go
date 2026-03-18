package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
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
	ignoredBlockedURIs := utils.DefaultIgnoredBlockedURIs
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

	r := mux.NewRouter()
	r.HandleFunc(*healthCheckPath, handler.HealthcheckHandler).Methods("GET")
	registry := prometheus.NewRegistry()
	m := metrics.New(registry)

	wrapWithPrometheus := func(handlerName string, route string, h http.Handler) http.Handler {
		labels := prometheus.Labels{"handler": handlerName, "route": route}
		return promhttp.InstrumentHandlerDuration(
			m.RequestDuration.MustCurryWith(labels),
			promhttp.InstrumentHandlerInFlight(m.RequestsInFlight.With(labels), h),
		)
	}

	r.Handle("/csp/report-only", wrapWithPrometheus("csp", "/csp/report-only", &handler.CSPViolationReportHandler{
		BlockedURIs:                 ignoredBlockedURIs,
		BlockedDomains:              blockedDomains,
		TruncateQueryStringFragment: *truncateQueryStringFragment,

		LogClientIP:          *logClientIP,
		LogTruncatedClientIP: *logTruncatedClientIP,
		MetadataObject:       *metadataObject,
		Logger:               logger,
		ReportOnly:           true,
		Metrics:              m,
	})).Methods("POST")

	r.Handle("/csp", wrapWithPrometheus("csp", "/csp", &handler.CSPViolationReportHandler{
		BlockedURIs:                 ignoredBlockedURIs,
		BlockedDomains:              blockedDomains,
		TruncateQueryStringFragment: *truncateQueryStringFragment,

		LogClientIP:          *logClientIP,
		LogTruncatedClientIP: *logTruncatedClientIP,
		MetadataObject:       *metadataObject,
		Logger:               logger,
		ReportOnly:           false,
		Metrics:              m,
	})).Methods("POST")

	r.Handle("/nel/report-only", wrapWithPrometheus("nel", "/nel/report-only", &handler.NELViolationReportHandler{
		TruncateQueryStringFragment: *truncateQueryStringFragment,

		LogClientIP:          *logClientIP,
		LogTruncatedClientIP: *logTruncatedClientIP,
		MetadataObject:       *metadataObject,
		Logger:               logger,
		ReportOnly:           true,
		Metrics:              m,
	})).Methods("POST")

	r.Handle("/nel", wrapWithPrometheus("nel", "/nel", &handler.NELViolationReportHandler{
		TruncateQueryStringFragment: *truncateQueryStringFragment,

		LogClientIP:          *logClientIP,
		LogTruncatedClientIP: *logTruncatedClientIP,
		MetadataObject:       *metadataObject,
		Logger:               logger,
		ReportOnly:           false,
		Metrics:              m,
	})).Methods("POST")

	r.HandleFunc("/reporting-api/csp", handler.ReportAPICorsHandler).Methods("OPTIONS")
	r.Handle("/reporting-api/csp", wrapWithPrometheus("reporting_api_csp", "/reporting-api/csp", &handler.ReportAPIViolationReportHandler{
		BlockedURIs:                 ignoredBlockedURIs,
		BlockedDomains:              blockedDomains,
		TruncateQueryStringFragment: *truncateQueryStringFragment,

		LogClientIP:          *logClientIP,
		LogTruncatedClientIP: *logTruncatedClientIP,
		MetadataObject:       *metadataObject,
		Logger:               logger,
		Metrics:              m,
	})).Methods("POST")

	r.Handle("/", wrapWithPrometheus("csp", "/", &handler.CSPViolationReportHandler{
		BlockedURIs:                 ignoredBlockedURIs,
		BlockedDomains:              blockedDomains,
		TruncateQueryStringFragment: *truncateQueryStringFragment,

		LogClientIP:          *logClientIP,
		LogTruncatedClientIP: *logTruncatedClientIP,
		MetadataObject:       *metadataObject,
		Logger:               logger,
		ReportOnly:           false,
		Metrics:              m,
	})).Methods("POST")

	r.NotFoundHandler = r.NewRoute().HandlerFunc(http.NotFound).GetHandler()

	logger.Debugf("blocked URI list: %s", ignoredBlockedURIs)
	logger.Debugf("blocked domain list: %s", blockedDomains)
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
