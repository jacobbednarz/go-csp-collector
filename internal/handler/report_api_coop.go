package handler

import (
	"net/http"
)

// COOPReport is a Cross-Origin-Opener-Policy violation delivered by the
// Reporting API (https://html.spec.whatwg.org/multipage/browsers.html#coop-reporting).
type COOPReport struct {
	Age       int            `json:"age"`
	Body      COOPReportBody `json:"body"`
	Type      string         `json:"type"`
	URL       string         `json:"url"`
	UserAgent string         `json:"user_agent"`
}

// ReportType satisfies ReportTyped.
func (r COOPReport) ReportType() string { return r.Type }

// COOPReportBody holds every field a COOP violation can carry. Which ones
// are set depends on Type: "navigation-to-response",
// "navigation-from-response", or one of the six "access-from-coop-page-to-*"
// and "access-to-coop-page-from-*" types. The access report URL fields use
// the names Chrome and the web-platform-tests send (openeeURL,
// initialPopupURL, otherDocumentURL), which differ from the HTML spec prose.
type COOPReportBody struct {
	Disposition         string `json:"disposition"`
	EffectivePolicy     string `json:"effectivePolicy"`
	Type                string `json:"type"`
	PreviousResponseURL string `json:"previousResponseURL"`
	NextResponseURL     string `json:"nextResponseURL"`
	Referrer            string `json:"referrer"`
	Property            string `json:"property"`
	OpenerURL           string `json:"openerURL"`
	OpeneeURL           string `json:"openeeURL"`
	InitialPopupURL     string `json:"initialPopupURL"`
	OtherDocumentURL    string `json:"otherDocumentURL"`
	SourceFile          string `json:"sourceFile"`
	LineNumber          int    `json:"lineNumber"`
	ColumnNumber        int    `json:"columnNumber"`
}

// NewReportAPICOOPHandler builds the reporting-api/coop handler on BatchReportHandler.
func NewReportAPICOOPHandler(opts Options) http.Handler {
	return &BatchReportHandler[COOPReport]{
		HandlerName:  "reporting_api_coop",
		ExpectedType: "coop",
		Options:      opts,

		SetResponseHeaders: setCORSResponseHeaders,

		Validate: func(report COOPReport) *Rejection {
			return requireHTTPURL("url", report.URL)
		},

		Process: func(report COOPReport) ProcessResult {
			// COOP's report-only disposition is "reporting", unlike CSP's "report".
			reportOnly := report.Body.Disposition == "reporting"
			lf := Fields{
				"report_only":           reportOnly,
				"url":                   report.URL,
				"type":                  report.Body.Type,
				"disposition":           report.Body.Disposition,
				"effective_policy":      report.Body.EffectivePolicy,
				"previous_response_url": report.Body.PreviousResponseURL,
				"next_response_url":     report.Body.NextResponseURL,
				"referrer":              report.Body.Referrer,
				"property":              report.Body.Property,
				"opener_url":            report.Body.OpenerURL,
				"openee_url":            report.Body.OpeneeURL,
				"initial_popup_url":     report.Body.InitialPopupURL,
				"other_document_url":    report.Body.OtherDocumentURL,
				"source_file":           report.Body.SourceFile,
				"line_number":           report.Body.LineNumber,
				"column_number":         report.Body.ColumnNumber,
			}

			if opts.TruncateQueryStringFragment {
				truncateURLFields(lf, "url", "previous_response_url", "next_response_url", "referrer",
					"opener_url", "openee_url", "initial_popup_url", "other_document_url", "source_file")
			}

			return ProcessResult{Fields: lf, Mode: modeLabel(reportOnly)}
		},
	}
}
