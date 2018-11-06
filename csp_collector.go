package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// CSPReport is the structure of the HTTP payload the system receives.
type CSPReport struct {
	Body struct {
		DocumentURI        string `json:"document-uri"`
		Referrer           string `json:"referrer"`
		BlockedURI         string `json:"blocked-uri"`
		ViolatedDirective  string `json:"violated-directive"`
		EffectiveDirective string `json:"effective-directive"`
		OriginalPolicy     string `json:"original-policy"`
		Disposition        string `json:"disposition"`
		ScriptSample       string `json:"script-sample"`
		StatusCode         string `json:"status-code"`
	} `json:"csp-report"`
}

var (
	// Rev is set at build time and holds the revision that the package
	// was created at.
	Rev = "dev"

	debug *log.Logger

	// Flag for toggling verbose output.
	debugFlag bool
)

func setupDebugLogger(debugHandle io.Writer) {
	debug = log.New(debugHandle, "[DEBUG] ", log.Lmicroseconds)
}

func main() {
	setupDebugLogger(os.Stdout)

	version := flag.Bool("version", false, "Display the version")
	flag.BoolVar(&debugFlag, "debug", false, "Output additional logging for debugging")

	flag.Parse()

	if *version {
		fmt.Printf("csp-collector (%s)\n", Rev)
		os.Exit(0)
	}

	if debugFlag {
		debug.Println("Starting up...")
	}

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
		return
	}

	decoder := json.NewDecoder(r.Body)
	var report CSPReport

	err := decoder.Decode(&report)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		return
	}
	defer r.Body.Close()

	reportValidation := validateViolation(report)
	if reportValidation != nil {
		http.Error(w, reportValidation.Error(), http.StatusBadRequest)
		return
	}

	reportData := formatReport(report)

	// Set flag to 0 here so that we control the logger output here and it doesn't
	// prefix everything with an additional timestamp.
	log.SetFlags(0)
	log.Println(reportData)
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
	}

	for _, value := range ignoredBlockedURIs {
		if strings.HasPrefix(r.Body.BlockedURI, value) == true {
			err := fmt.Errorf("blocked URI ('%s') is an invalid resource", value)
			return err
		}
	}

	return nil
}

func formatReport(r CSPReport) string {
	s := []string{}

	s = append(s, fmt.Sprintf(`timestamp="%s"`, time.Now().UTC().Format("2006-01-02T15:04:05Z07:00")))
	s = append(s, fmt.Sprintf(`document_uri="%s"`, r.Body.DocumentURI))
	s = append(s, fmt.Sprintf(`referrer="%s"`, r.Body.Referrer))
	s = append(s, fmt.Sprintf(`blocked_uri="%s"`, r.Body.BlockedURI))
	s = append(s, fmt.Sprintf(`violated_directive="%s"`, r.Body.ViolatedDirective))
	s = append(s, fmt.Sprintf(`effective_directive="%s"`, r.Body.EffectiveDirective))
	s = append(s, fmt.Sprintf(`original_policy="%s"`, r.Body.OriginalPolicy))
	s = append(s, fmt.Sprintf(`disposition="%s"`, r.Body.Disposition))
	s = append(s, fmt.Sprintf(`script_sample="%s"`, r.Body.ScriptSample))
	s = append(s, fmt.Sprintf(`status_code="%s"`, r.Body.StatusCode))

	return strings.Join(s, " ")
}
