package handler

import (
	"fmt"
	"net/http"
	"strings"
)

// COEPReport is a Cross-Origin-Embedder-Policy violation delivered by the
// Reporting API (https://html.spec.whatwg.org/multipage/browsers.html#embedder-policy-checks).
type COEPReport struct {
	Age       int            `json:"age"`
	Body      COEPReportBody `json:"body"`
	Type      string         `json:"type"`
	URL       string         `json:"url"`
	UserAgent string         `json:"user_agent"`
}

func (r COEPReport) ReportType() string { return r.Type }

// COEPReportBody describes the blocked load. Type is "corp", "navigation"
// or "worker initialization"; Destination is only set for "corp".
type COEPReportBody struct {
	Type        string `json:"type"`
	BlockedURL  string `json:"blockedURL"`
	Destination string `json:"destination"`
	Disposition string `json:"disposition"`
}

// NewReportAPICOEPHandler builds the reporting-api/coep handler on BatchReportHandler.
func NewReportAPICOEPHandler(opts Options) http.Handler {
	return &BatchReportHandler[COEPReport]{
		HandlerName:  "reporting_api_coep",
		ExpectedType: "coep",
		Options:      opts,

		SetResponseHeaders: setCORSResponseHeaders,

		Validate: func(report COEPReport) (string, error) {
			if !strings.HasPrefix(report.URL, "http") {
				return "validation_error", fmt.Errorf("url ('%s') is invalid", report.URL)
			}
			return "", nil
		},

		Process: func(report COEPReport, r *http.Request, metadata interface{}) ProcessResult {
			// COEP's report-only disposition is "reporting", unlike CSP's "report".
			reportOnly := report.Body.Disposition == "reporting"
			lf := Fields{
				"report_only": reportOnly,
				"url":         report.URL,
				"type":        report.Body.Type,
				"blocked_uri": report.Body.BlockedURL,
				"destination": report.Body.Destination,
				"disposition": report.Body.Disposition,
				"metadata":    metadata,
				"path":        r.URL.Path,
			}

			if opts.TruncateQueryStringFragment {
				truncateURLFields(lf, "url", "blocked_uri")
			}

			mode := "enforced"
			if reportOnly {
				mode = "report_only"
			}

			return ProcessResult{Fields: lf, Mode: mode}
		},
	}
}
