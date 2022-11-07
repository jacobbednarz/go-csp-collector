package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// CSPReport is the structure of the HTTP payload the system receives.
type CSPReport struct {
	Body CSPReportBody `json:"csp-report"`
}

// CSPReportBody contains the fields that are nested within the
// violation report.
type CSPReportBody struct {
	DocumentURI        string      `json:"document-uri"`
	Referrer           string      `json:"referrer"`
	BlockedURI         string      `json:"blocked-uri"`
	ViolatedDirective  string      `json:"violated-directive"`
	EffectiveDirective string      `json:"effective-directive"`
	OriginalPolicy     string      `json:"original-policy"`
	Disposition        string      `json:"disposition"`
	ScriptSample       string      `json:"script-sample"`
	StatusCode         interface{} `json:"status-code"`
}

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

	// Default URI Filter list.
	defaultIgnoredBlockedURIs = []string{
		"resource://",
		"chromenull://",
		"chrome-extension://",
		"safari-extension://",
		"mxjscall://",
		"webviewprogressproxy://",
		"res://",
		"mx://",
		"safari-resource://",
		"chromeinvoke://",
		"chromeinvokeimmediate://",
		"mbinit://",
		"opera://",
		"ms-appx://",
		"ms-appx-web://",
		"localhost",
		"127.0.0.1",
		"none://",
		"about:blank",
		"android-webview",
		"ms-browser-extension",
		"wvjbscheme://__wvjb_queue_message__",
		"nativebaiduhd://adblock",
		"bdvideo://error",
	}
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func trimEmptyAndComments(s []string) []string {
	var r []string
	for _, str := range s {
		if str == "" {
			continue
		}

		// ignore comments
		if strings.HasPrefix(str, "#") {
			continue
		}

		r = append(r, str)
	}
	return r
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
		log.SetLevel(log.DebugLevel)
	}

	if *outputFormat == "json" {
		log.SetFormatter(&log.JSONFormatter{
			FieldMap: logFieldMapDefaults,
		})
	} else {
		log.SetFormatter(&log.TextFormatter{
			FullTimestamp:          true,
			DisableLevelTruncation: true,
			QuoteEmptyFields:       true,
			DisableColors:          true,
			FieldMap:               logFieldMapDefaults,
		})
	}

	log.Debug("Starting up...")
	ignoredBlockedURIs := defaultIgnoredBlockedURIs
	if *blockedURIFile != "" {
		log.Debugf("Using Filter list from file at: %s\n", *blockedURIFile)

		content, err := ioutil.ReadFile(*blockedURIFile)
		if err != nil {
			log.Fatalf("Error reading Blocked File list: %s", *blockedURIFile)
		}
		ignoredBlockedURIs = trimEmptyAndComments(strings.Split(string(content), "\n"))
	} else {
		log.Debug("Using Filter list from internal list")
	}

	log.Debugf("Blocked URI List: %s", ignoredBlockedURIs)
	log.Debugf("Listening on TCP Port: %s", strconv.Itoa(*listenPort))

	http.HandleFunc(*healthCheckPath, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		w.WriteHeader(http.StatusOK)
	})

	http.Handle("/", &violationReportHandler{
		blockedURIs:                 ignoredBlockedURIs,
		truncateQueryStringFragment: *truncateQueryStringFragment,

		logClientIP:          *logClientIP,
		logTruncatedClientIP: *logTruncatedClientIP,
		metadataObject:       *metadataObject,
	})
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", strconv.Itoa(*listenPort)), nil))
}

type violationReportHandler struct {
	truncateQueryStringFragment bool
	blockedURIs                 []string

	logClientIP          bool
	logTruncatedClientIP bool
	metadataObject       bool
}

func (vrh *violationReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		log.WithFields(log.Fields{
			"http_method": r.Method,
		}).Debug("Received invalid HTTP method")

		return
	}

	decoder := json.NewDecoder(r.Body)
	var report CSPReport

	err := decoder.Decode(&report)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		log.Debugf("Unable to decode invalid JSON payload: %s", err)
		return
	}
	defer r.Body.Close()

	reportValidation := vrh.validateViolation(report)
	if reportValidation != nil {
		http.Error(w, reportValidation.Error(), http.StatusBadRequest)
		log.Debugf("Received invalid payload: %s", reportValidation.Error())
		return
	}

	var metadata interface{}
	if vrh.metadataObject {
		metadataMap := make(map[string]string)
		query := r.URL.Query()

		for k, v := range query {
			metadataMap[k] = v[0]
		}

		metadata = metadataMap
	} else {
		metadatas, gotMetadata := r.URL.Query()["metadata"]
		if gotMetadata {
			metadata = metadatas[0]
		}
	}

	lf := log.Fields{
		"document_uri":        report.Body.DocumentURI,
		"referrer":            report.Body.Referrer,
		"blocked_uri":         report.Body.BlockedURI,
		"violated_directive":  report.Body.ViolatedDirective,
		"effective_directive": report.Body.EffectiveDirective,
		"original_policy":     report.Body.OriginalPolicy,
		"disposition":         report.Body.Disposition,
		"script_sample":       report.Body.ScriptSample,
		"status_code":         report.Body.StatusCode,
		"metadata":            metadata,
		"path":                r.URL.Path,
	}

	if vrh.truncateQueryStringFragment {
		lf["document_uri"] = truncateQueryStringFragment(report.Body.DocumentURI)
		lf["referrer"] = truncateQueryStringFragment(report.Body.Referrer)
		lf["blocked_uri"] = truncateQueryStringFragment(report.Body.BlockedURI)
	}

	if vrh.logClientIP {
		ip, err := getClientIP(r)
		if err != nil {
			log.Warnf("unable to parse client ip: %s", err)
		}
		lf["client_ip"] = ip.String()
	}

	if vrh.logTruncatedClientIP {
		ip, err := getClientIP(r)
		if err != nil {
			log.Warnf("unable to parse client ip: %s", err)
		}
		lf["client_ip"] = truncateClientIP(ip)
	}

	log.WithFields(lf).Info()
}

func (vrh *violationReportHandler) validateViolation(r CSPReport) error {
	for _, value := range vrh.blockedURIs {
		if strings.HasPrefix(r.Body.BlockedURI, value) {
			err := fmt.Errorf("blocked URI ('%s') is an invalid resource", value)
			return err
		}
	}

	if !strings.HasPrefix(r.Body.DocumentURI, "http") {
		return fmt.Errorf("document URI ('%s') is invalid", r.Body.DocumentURI)
	}

	return nil
}

func truncateQueryStringFragment(uri string) string {
	idx := strings.IndexAny(uri, "#?")
	if idx != -1 {
		return uri[:idx]
	}

	return uri
}

func truncateClientIP(addr netip.Addr) string {
	// Ignoring the error is statically safe, as there are always enough bits.
	if addr.Is4() {
		p, _ := addr.Prefix(24)
		return p.String()
	}

	if addr.Is6() {
		p, _ := addr.Prefix(64)
		return p.String()
	}

	return "unknown-address"
}

func getClientIP(r *http.Request) (netip.Addr, error) {
	if s := r.Header.Get("X-Forwarded-For"); s != "" {
		addr, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Addr{}, fmt.Errorf("unable to parse address from X-Forwarded-For=%s: %w", s, err)
		}

		return addr, nil
	}

	addrp, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("unable to parse remote address %s: %w", r.RemoteAddr, err)
	}

	return addrp.Addr(), nil
}
