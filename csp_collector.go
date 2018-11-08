package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
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

var (
	// Rev is set at build time and holds the revision that the package
	// was created at.
	Rev = "dev"

	// Flag for toggling verbose output.
	debugFlag bool

	// Flag for toggling output format.
	outputFormat string

	// Shared defaults for the logger output. This ensures that we are
	// using the same keys for the `FieldKey` values across both formatters.
	logFieldMapDefaults = log.FieldMap{
		log.FieldKeyTime:  "timestamp",
		log.FieldKeyLevel: "level",
		log.FieldKeyMsg:   "message",
	}
)

func init() {
	log.SetOutput(os.Stdout)
	log.SetLevel(log.InfoLevel)
}

func main() {
	version := flag.Bool("version", false, "Display the version")
	flag.BoolVar(&debugFlag, "debug", false, "Output additional logging for debugging")
	flag.StringVar(&outputFormat, "output-format", "text", "Define how the violation reports are formatted for output.\nDefaults to 'text'. Valid options are 'text' or 'json'")

	flag.Parse()

	if *version {
		fmt.Printf("csp-collector (%s)\n", Rev)
		os.Exit(0)
	}

	if debugFlag {
		log.SetLevel(log.DebugLevel)
	}

	if outputFormat == "json" {
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

	http.HandleFunc("/", handleViolationReport)
	log.Fatal(http.ListenAndServe(":8080", nil))
}

func handleViolationReport(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" && r.URL.Path == "/_healthcheck" {
		w.WriteHeader(http.StatusOK)
		return
	}

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
		log.Debug(fmt.Sprintf("Unable to decode invalid JSON payload: %s", err))
		return
	}
	defer r.Body.Close()

	reportValidation := validateViolation(report)
	if reportValidation != nil {
		http.Error(w, reportValidation.Error(), http.StatusBadRequest)
		log.Debug(fmt.Sprintf("Received invalid payload: %s", reportValidation.Error()))
		return
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
	}).Info()
}

func validateViolation(r CSPReport) error {
	ignoredBlockedURIs := []string{
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

	for _, value := range ignoredBlockedURIs {
		if strings.HasPrefix(r.Body.BlockedURI, value) == true {
			err := fmt.Errorf("blocked URI ('%s') is an invalid resource", value)
			return err
		}
	}

	return nil
}
