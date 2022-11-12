package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/handler"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"

	"github.com/gorilla/mux"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
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
	logFieldMapDefaults = log.FieldMap{
		log.FieldKeyTime:  "timestamp",
		log.FieldKeyLevel: "level",
		log.FieldKeyMsg:   "message",
	}
)

var logger = logrus.New()

func init() {
	logger.SetOutput(os.Stdout)
	logger.SetLevel(log.InfoLevel)
}

func main() {
	version := flag.Bool("version", false, "Display the version")
	debugFlag := flag.Bool("debug", false, "Output additional logging for debugging")
	outputFormat := flag.String("output-format", "text", "Define how the violation reports are formatted for output.\nDefaults to 'text'. Valid options are 'text' or 'json'")
	blockedURIFile := flag.String("filter-file", "", "Blocked URI Filter file")
	listenPort := flag.Int("port", 8080, "Port to listen on")
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
		logger.SetLevel(log.DebugLevel)
	}

	if *outputFormat == "json" {
		logger.SetFormatter(&log.JSONFormatter{
			FieldMap: logFieldMapDefaults,
		})
	} else {
		logger.SetFormatter(&log.TextFormatter{
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
			log.Fatalf("error reading Blocked File list: %s", *blockedURIFile)
		}
		ignoredBlockedURIs = utils.TrimEmptyAndComments(strings.Split(string(content), "\n"))
	} else {
		logger.Debug("using filter list from internal list")
	}

	r := mux.NewRouter()
	r.HandleFunc(*healthCheckPath, handler.HealthcheckHandler).Methods("GET")

	cspHandler := &handler.CSPViolationReportHandler{
		BlockedURIs:                 ignoredBlockedURIs,
		TruncateQueryStringFragment: *truncateQueryStringFragment,

		LogClientIP:          *logClientIP,
		LogTruncatedClientIP: *logTruncatedClientIP,
		MetadataObject:       *metadataObject,
		Logger:               logger,
	}

	reportOnlyCspHandler := cspHandler
	reportOnlyCspHandler.ReportOnly = true

	r.Handle("/csp", cspHandler).Methods("POST")
	r.Handle("/csp/report-only", reportOnlyCspHandler).Methods("POST")
	r.Handle("/", cspHandler).Methods("POST")

	r.NotFoundHandler = r.NewRoute().HandlerFunc(http.NotFound).GetHandler()

	logger.Debugf("blocked URI list: %s", ignoredBlockedURIs)
	logger.Debugf("listening on TCP port: %s", strconv.Itoa(*listenPort))

	logger.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", strconv.Itoa(*listenPort)), r))
}
