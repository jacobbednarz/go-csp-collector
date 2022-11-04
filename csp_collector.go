package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
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
	ignoredBlockedURIs = []string{
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

	http.HandleFunc("/", handleViolationReport)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", strconv.Itoa(*listenPort)), nil))
}

func handleViolationReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
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

	reportValidation := validateViolation(report)
	if reportValidation != nil {
		http.Error(w, reportValidation.Error(), http.StatusBadRequest)
		log.Debugf("Received invalid payload: %s", reportValidation.Error())
		return
	}

	metadatas, gotMetadata := r.URL.Query()["metadata"]
	var metadata string
	if gotMetadata {
		metadata = metadatas[0]
	}

	log.WithFields(log.Fields{
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
	}).Info()
}

func validateViolation(r CSPReport) error {
	for _, value := range ignoredBlockedURIs {
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
