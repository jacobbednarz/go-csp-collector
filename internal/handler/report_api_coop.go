package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
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
func NewReportAPICOOPHandler(truncateQueryStringFragment, logClientIP, logTruncatedClientIP, metadataObject bool, logger *slog.Logger, m *metrics.Metrics) http.Handler {
	return &BatchReportHandler[COOPReport]{
		HandlerName:          "reporting_api_coop",
		ExpectedType:         "coop",
		MetadataObject:       metadataObject,
		LogClientIP:          logClientIP,
		LogTruncatedClientIP: logTruncatedClientIP,
		Logger:               logger,
		Metrics:              m,

		SetResponseHeaders: setCORSResponseHeaders,

		Validate: func(report COOPReport) (string, error) {
			if !strings.HasPrefix(report.URL, "http") {
				return "validation_error", fmt.Errorf("url ('%s') is invalid", report.URL)
			}
			return "", nil
		},

		Process: func(report COOPReport, r *http.Request, metadata interface{}) ProcessResult {
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
				"metadata":              metadata,
				"path":                  r.URL.Path,
			}

			if truncateQueryStringFragment {
				truncateURLFields(lf, "url", "previous_response_url", "next_response_url", "referrer",
					"opener_url", "openee_url", "initial_popup_url", "other_document_url", "source_file")
			}

			mode := "enforced"
			if reportOnly {
				mode = "report_only"
			}

			return ProcessResult{Fields: lf, Mode: mode}
		},
	}
}
