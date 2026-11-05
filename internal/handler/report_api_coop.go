package handler

import (
	"log/slog"
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
			if opts.TruncateQueryStringFragment {
				report.URL = truncateQueryStringFragment(report.URL)
				report.Body.PreviousResponseURL = truncateQueryStringFragment(report.Body.PreviousResponseURL)
				report.Body.NextResponseURL = truncateQueryStringFragment(report.Body.NextResponseURL)
				report.Body.Referrer = truncateQueryStringFragment(report.Body.Referrer)
				report.Body.OpenerURL = truncateQueryStringFragment(report.Body.OpenerURL)
				report.Body.OpeneeURL = truncateQueryStringFragment(report.Body.OpeneeURL)
				report.Body.InitialPopupURL = truncateQueryStringFragment(report.Body.InitialPopupURL)
				report.Body.OtherDocumentURL = truncateQueryStringFragment(report.Body.OtherDocumentURL)
				report.Body.SourceFile = truncateQueryStringFragment(report.Body.SourceFile)
			}

			attrs := make([]slog.Attr, 0, 16+maxRequestAttrs)
			attrs = append(attrs,
				slog.Int("column_number", report.Body.ColumnNumber),
				slog.String("disposition", report.Body.Disposition),
				slog.String("effective_policy", report.Body.EffectivePolicy),
				slog.String("initial_popup_url", report.Body.InitialPopupURL),
				slog.Int("line_number", report.Body.LineNumber),
				slog.String("next_response_url", report.Body.NextResponseURL),
				slog.String("openee_url", report.Body.OpeneeURL),
				slog.String("opener_url", report.Body.OpenerURL),
				slog.String("other_document_url", report.Body.OtherDocumentURL),
				slog.String("previous_response_url", report.Body.PreviousResponseURL),
				slog.String("property", report.Body.Property),
				slog.String("referrer", report.Body.Referrer),
				slog.Bool("report_only", reportOnly),
				slog.String("source_file", report.Body.SourceFile),
				slog.String("type", report.Body.Type),
				slog.String("url", report.URL),
			)

			return ProcessResult{Attrs: attrs, Mode: modeLabel(reportOnly)}
		},
	}
}
