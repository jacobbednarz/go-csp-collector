package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	log "github.com/sirupsen/logrus"
)

// isBlockedByDomain returns true when the hostname of blockedURI exactly
// matches domain or is a subdomain of domain (e.g. "foo.example.com" matches
// "example.com"). The check is an exact suffix comparison, not fuzzy matching.
func isBlockedByDomain(blockedURI string, domains []string) bool {
	if len(domains) == 0 {
		return false
	}

	u, err := url.Parse(blockedURI)
	if err != nil || u.Host == "" {
		return false
	}

	host := u.Hostname()
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
}

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
	SourceFile         string      `json:"source-file"`
	LineNumber         uint32      `json:"line-number"`
	ColumnNumber       uint32      `json:"column-number"`
}

type CSPViolationReportHandler struct {
	ReportOnly                  bool
	TruncateQueryStringFragment bool
	BlockedURIs                 []string
	BlockedDomains              []string

	LogClientIP          bool
	LogTruncatedClientIP bool
	MetadataObject       bool

	Logger  *log.Logger
	Metrics *metrics.Metrics
}

func (vrh *CSPViolationReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var report CSPReport

	err := decoder.Decode(&report)
	if err != nil {
		if vrh.Metrics != nil {
			vrh.Metrics.ReportErrors.WithLabelValues("csp", "decode_error").Inc()
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		vrh.Logger.Debugf("unable to decode invalid JSON payload: %s", err)
		return
	}

	defer r.Body.Close()

	for _, value := range vrh.BlockedURIs {
		if strings.HasPrefix(report.Body.BlockedURI, value) {
			if vrh.Metrics != nil {
				vrh.Metrics.ReportFiltered.WithLabelValues("csp", "blocked_uri").Inc()
			}
			http.Error(w, fmt.Sprintf("blocked URI ('%s') is an invalid resource", value), http.StatusBadRequest)
			vrh.Logger.Debugf("received invalid payload: blocked URI ('%s') is an invalid resource", value)
			return
		}
	}

	if isBlockedByDomain(report.Body.BlockedURI, vrh.BlockedDomains) {
		if vrh.Metrics != nil {
			vrh.Metrics.ReportFiltered.WithLabelValues("csp", "blocked_domain").Inc()
		}
		http.Error(w, fmt.Sprintf("blocked URI ('%s') is an invalid resource", report.Body.BlockedURI), http.StatusBadRequest)
		vrh.Logger.Debugf("received invalid payload: blocked URI ('%s') is an invalid resource", report.Body.BlockedURI)
		return
	}

	reportValidation := vrh.validateViolation(report)
	if reportValidation != nil {
		if vrh.Metrics != nil {
			vrh.Metrics.ReportErrors.WithLabelValues("csp", "validation_error").Inc()
		}
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

	lf := log.Fields{
		"report_only":         vrh.ReportOnly,
		"document_uri":        report.Body.DocumentURI,
		"referrer":            report.Body.Referrer,
		"blocked_uri":         report.Body.BlockedURI,
		"violated_directive":  report.Body.ViolatedDirective,
		"effective_directive": report.Body.EffectiveDirective,
		"original_policy":     report.Body.OriginalPolicy,
		"disposition":         report.Body.Disposition,
		"script_sample":       report.Body.ScriptSample,
		"status_code":         report.Body.StatusCode,
		"source_file":         report.Body.SourceFile,
		"line_number":         report.Body.LineNumber,
		"column_number":       report.Body.ColumnNumber,
		"metadata":            metadata,
		"path":                r.URL.Path,
	}

	if vrh.TruncateQueryStringFragment {
		lf["document_uri"] = utils.TruncateQueryStringFragment(report.Body.DocumentURI)
		lf["referrer"] = utils.TruncateQueryStringFragment(report.Body.Referrer)
		lf["blocked_uri"] = utils.TruncateQueryStringFragment(report.Body.BlockedURI)
		lf["source_file"] = utils.TruncateQueryStringFragment(report.Body.SourceFile)
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
	if vrh.Metrics != nil {
		mode := "enforced"
		if vrh.ReportOnly {
			mode = "report_only"
		}
		vrh.Metrics.Reports.WithLabelValues("csp", mode).Inc()
	}
}

func (vrh *CSPViolationReportHandler) validateViolation(r CSPReport) error {
	for _, value := range vrh.BlockedURIs {
		if strings.HasPrefix(r.Body.BlockedURI, value) {
			return fmt.Errorf("blocked URI ('%s') is an invalid resource", value)
		}
	}

	if isBlockedByDomain(r.Body.BlockedURI, vrh.BlockedDomains) {
		return fmt.Errorf("blocked URI ('%s') is an invalid resource", r.Body.BlockedURI)
	}

	if !strings.HasPrefix(r.Body.DocumentURI, "http") {
		return fmt.Errorf("document URI ('%s') is invalid", r.Body.DocumentURI)
	}

	return nil
}
