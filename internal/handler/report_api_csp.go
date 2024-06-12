package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	log "github.com/sirupsen/logrus"
)

// CSPReport is the structure of the HTTP payload the system receives.
type ReportAPIReports struct {
	Reports []ReportAPIReport `json:"reports"`
}

type ReportAPIReport struct {
	Age       int                `json:"age"`
	Body      ReportAPIViolation `json:"body"`
	Type      string             `json:"type"`
	URL       string             `json:"url"`
	UserAgent string             `json:"user_agent"`
}

type ReportAPIViolation struct {
	BlockedURL         string `json:"blockedURL"`
	ColumnNumber       int    `json:"columnNumber,omitempty"`
	Disposition        string `json:"disposition"`
	DocumentURL        string `json:"documentURL"`
	EffectiveDirective string `json:"effectiveDirective"`
	LineNumber         int    `json:"lineNumber"`
	OriginalPolicy     string `json:"originalPolicy"`
	Referrer           string `json:"referrer"`
	Sample             string `json:"sample,omitempty"`
	SourceFile         string `json:"sourceFile"`
	StatusCode         int    `json:"statusCode"`
}

type ReportAPIViolationReportHandler struct {
	TruncateQueryStringFragment bool
	BlockedURIs                 []string

	LogClientIP          bool
	LogTruncatedClientIP bool
	MetadataObject       bool

	Logger *log.Logger
}

func (vrh *ReportAPIViolationReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var reports_raw []ReportAPIReport

	err := decoder.Decode(&reports_raw)
	if err != nil {
		w.WriteHeader(http.StatusUnprocessableEntity)
		vrh.Logger.Debugf("unable to decode invalid JSON payload: %s", err)
		return
	}

	defer r.Body.Close()

	reports := ReportAPIReports{
		Reports: reports_raw,
	}

	reportValidation := vrh.validateViolation(reports)
	if reportValidation != nil {
		http.Error(w, reportValidation.Error(), http.StatusBadRequest)
		vrh.Logger.Debugf("received invalid payload: %s", reportValidation.Error())
		return
	}

	var metadata interface{}
	if vrh.MetadataObject {
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

	for _, violation := range reports.Reports {
		report_only := violation.Body.Disposition == "report"
		lf := log.Fields{
			"report_only":         report_only,
			"document_uri":        violation.Body.DocumentURL,
			"referrer":            violation.Body.Referrer,
			"blocked_uri":         violation.Body.BlockedURL,
			"violated_directive":  violation.Body.EffectiveDirective,
			"effective_directive": violation.Body.EffectiveDirective,
			"original_policy":     violation.Body.OriginalPolicy,
			"disposition":         violation.Body.Disposition,
			"status_code":         violation.Body.StatusCode,
			"source_file":         violation.Body.SourceFile,
			"line_number":         violation.Body.LineNumber,
			"column_number":       violation.Body.ColumnNumber,
			"metadata":            metadata,
			"path":                r.URL.Path,
		}

		if vrh.TruncateQueryStringFragment {
			lf["document_uri"] = utils.TruncateQueryStringFragment(violation.Body.DocumentURL)
			lf["referrer"] = utils.TruncateQueryStringFragment(violation.Body.Referrer)
			lf["blocked_uri"] = utils.TruncateQueryStringFragment(violation.Body.BlockedURL)
			lf["source_file"] = utils.TruncateQueryStringFragment(violation.Body.SourceFile)
		}

		if vrh.LogClientIP {
			ip, err := utils.GetClientIP(r)
			if err != nil {
				vrh.Logger.Warnf("unable to parse client ip: %s", err)
			}
			lf["client_ip"] = ip.String()
		}

		if vrh.LogTruncatedClientIP {
			ip, err := utils.GetClientIP(r)
			if err != nil {
				vrh.Logger.Warnf("unable to parse client ip: %s", err)
			}
			lf["client_ip"] = utils.TruncateClientIP(ip)
		}

		vrh.Logger.WithFields(lf).Info()
	}

}

func (vrh *ReportAPIViolationReportHandler) validateViolation(r ReportAPIReports) error {
	for _, violation := range r.Reports {
		if violation.Type != "csp-violation" {
			continue // Skip the rest of the loop and move to the next iteration
		}
		for _, value := range vrh.BlockedURIs {
			if strings.HasPrefix(violation.Body.BlockedURL, value) {
				err := fmt.Errorf("blocked URI ('%s') is an invalid resource", value)
				return err
			}
		}
		if !strings.HasPrefix(violation.Body.DocumentURL, "http") {
			return fmt.Errorf("document URI ('%s') is invalid", violation.Body.DocumentURL)
		}
	}

	return nil
}

func ReportAPICorsHandler(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	method := r.Header.Get("Access-Control-Request-Method")
	header := r.Header.Get("Access-Control-Request-Headers")
	allow_origin := utils.Ternary(origin != "", origin, "*")
	allow_method := utils.Ternary(method != "", method, "*")
	allow_header := utils.Ternary(header != "", header, "*")
	// Special handling due to bug in Chrome
	// https://bugs.chromium.org/p/chromium/issues/detail?id=1152867
	w.Header().Set("Access-Control-Allow-Origin", allow_origin)
	w.Header().Set("Access-Control-Allow-Methods", allow_method)
	w.Header().Set("Access-Control-Max-Age", "60")
	w.Header().Set("Access-Control-Allow-Headers", allow_header)
	w.Header().Set("vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")

	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.Header().Set("Server", "cloudflare")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}
