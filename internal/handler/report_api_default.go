package handler

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
)

// DefaultReport is any report delivered to a Reporting API "default"
// endpoint: types with no header of their own (deprecation, intervention)
// and ones whose header didn't name an endpoint (permissions-policy). The
// body's shape depends on Type, so it's kept as raw JSON.
type DefaultReport struct {
	Age       int             `json:"age"`
	Body      json.RawMessage `json:"body"`
	Type      string          `json:"type"`
	URL       string          `json:"url"`
	UserAgent string          `json:"user_agent"`
}

// ReportType satisfies ReportTyped.
func (r DefaultReport) ReportType() string { return r.Type }

// knownReportTypes are the Reporting API types allowed as the default
// endpoint's metric mode label. The type is client controlled, so anything
// else is labelled "reporting-api-default" to keep the series bounded.
var knownReportTypes = []string{
	"coep",
	"coop",
	"crash",
	"csp-violation",
	"deprecation",
	"document-policy-violation",
	"integrity-violation",
	"intervention",
	"network-error",
	"permissions-policy-violation",
}

// NewReportAPIDefaultHandler builds the reporting-api/default handler on BatchReportHandler.
func NewReportAPIDefaultHandler(opts Options) http.Handler {
	return &BatchReportHandler[DefaultReport]{
		HandlerName: "reporting_api_default",
		Options:     opts,

		SetResponseHeaders: setCORSResponseHeaders,

		RecordSuccessMetric: reportSuccessMetric(opts.Metrics, "reporting_api_default", append([]string{"reporting-api-default"}, knownReportTypes...)...),

		Validate: func(report DefaultReport) *Rejection {
			return requireHTTPURL("url", report.URL)
		},

		Process: func(report DefaultReport) ProcessResult {
			attrs := make([]slog.Attr, 0, 3+maxRequestAttrs)

			// URLs inside a body of unknown shape can't be found reliably,
			// so truncation leaves the body out rather than log URLs the
			// operator asked to have stripped.
			if opts.TruncateQueryStringFragment {
				report.URL = truncateQueryStringFragment(report.URL)
			} else {
				attrs = append(attrs, slog.String("body", string(report.Body)))
			}

			attrs = append(attrs, slog.String("type", report.Type), slog.String("url", report.URL))

			mode := "reporting-api-default"
			if slices.Contains(knownReportTypes, report.Type) {
				mode = report.Type
			}

			return ProcessResult{Attrs: attrs, Mode: mode}
		},
	}
}
