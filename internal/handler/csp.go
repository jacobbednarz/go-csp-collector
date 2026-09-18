package handler

import (
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

// CSPReport is the structure of the HTTP payload delivered by CSP2's
// report-uri directive: a single, un-batched object per violation, never an
// array. This predates the Reporting API (and CSP3's report-to directive,
// which uses it instead) so it carries no `type` discriminator of its own.
type CSPReport struct {
	Body CSPReportBody `json:"csp-report"`
}

// ReportType satisfies ReportTyped for interface conformance with
// BatchReportHandler. NewCSPHandler leaves ExpectedType empty, so this
// value is never actually compared against anything.
func (r CSPReport) ReportType() string { return "csp-violation" }

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

// NewCSPHandler builds the legacy report-uri CSP handler on top of the
// shared BatchReportHandler, using AllowSingleObject to accept its
// single-object wire format through the same array-oriented decoder every
// other handler uses. reportOnly is closed over the same way NewNELHandler
// closes over its own reportOnly flag, since the original handler derived
// it from which route it was registered on, not from the report body.
func NewCSPHandler(reportOnly bool, blockedURIs, blockedDomains []string, truncateQueryStringFragment, logClientIP, logTruncatedClientIP, metadataObject bool, logger *log.Logger, m *metrics.Metrics) http.Handler {
	return &BatchReportHandler[CSPReport]{
		HandlerName:       "csp",
		AllowSingleObject: true,
		MetadataObject:    metadataObject,

		LogClientIP:          logClientIP,
		LogTruncatedClientIP: logTruncatedClientIP,
		Logger:               logger,
		Metrics:              m,

		Validate: func(items []CSPReport) (string, error) {
			for _, report := range items {
				for _, value := range blockedURIs {
					if strings.HasPrefix(report.Body.BlockedURI, value) {
						return "blocked_uri", fmt.Errorf("blocked URI ('%s') is an invalid resource", value)
					}
				}
				if isBlockedByDomain(report.Body.BlockedURI, blockedDomains) {
					return "blocked_domain", fmt.Errorf("blocked URI ('%s') is an invalid resource", report.Body.BlockedURI)
				}
				if !strings.HasPrefix(report.Body.DocumentURI, "http") {
					return "validation_error", fmt.Errorf("document URI ('%s') is invalid", report.Body.DocumentURI)
				}
			}
			return "", nil
		},

		RecordValidationErrorMetric: func(reason string) {
			if m == nil {
				return
			}
			switch reason {
			case "blocked_uri":
				m.ReportFiltered.WithLabelValues("csp", "blocked_uri").Inc()
			case "blocked_domain":
				m.ReportFiltered.WithLabelValues("csp", "blocked_domain").Inc()
			default:
				m.ReportErrors.WithLabelValues("csp", "validation_error").Inc()
			}
		},

		Process: func(report CSPReport, r *http.Request, metadata interface{}) ProcessResult {
			lf := log.Fields{
				"report_only":         reportOnly,
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

			if truncateQueryStringFragment {
				lf["document_uri"] = utils.TruncateQueryStringFragment(report.Body.DocumentURI)
				lf["referrer"] = utils.TruncateQueryStringFragment(report.Body.Referrer)
				lf["blocked_uri"] = utils.TruncateQueryStringFragment(report.Body.BlockedURI)
				lf["source_file"] = utils.TruncateQueryStringFragment(report.Body.SourceFile)
			}

			mode := "enforced"
			if reportOnly {
				mode = "report_only"
			}

			return ProcessResult{Fields: lf, Mode: mode}
		},
	}
}
