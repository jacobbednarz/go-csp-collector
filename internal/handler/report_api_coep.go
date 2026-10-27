package handler

import (
	"net/http"
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

		Validate: func(report COEPReport) *Rejection {
			return requireHTTPURL("url", report.URL)
		},

		Process: func(report COEPReport) ProcessResult {
			// COEP's report-only disposition is "reporting", unlike CSP's "report".
			reportOnly := report.Body.Disposition == "reporting"
			lf := Fields{
				"report_only": reportOnly,
				"url":         report.URL,
				"type":        report.Body.Type,
				"blocked_uri": report.Body.BlockedURL,
				"destination": report.Body.Destination,
				"disposition": report.Body.Disposition,
			}

			if opts.TruncateQueryStringFragment {
				truncateURLFields(lf, "url", "blocked_uri")
			}

			return ProcessResult{Fields: lf, Mode: modeLabel(reportOnly)}
		},
	}
}
