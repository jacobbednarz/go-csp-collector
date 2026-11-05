package handler

import (
	"cmp"
	"log/slog"
	"net/http"
)

// ReportAPIReport is a CSP violation delivered by the Reporting API, for
// policies that name an endpoint with report-to.
type ReportAPIReport struct {
	Age       int                `json:"age"`
	Body      ReportAPIViolation `json:"body"`
	Type      string             `json:"type"`
	URL       string             `json:"url"`
	UserAgent string             `json:"user_agent"`
}

// ReportType satisfies ReportTyped.
func (r ReportAPIReport) ReportType() string { return r.Type }

// ReportAPIViolation is the body of a ReportAPIReport.
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

// NewReportAPICSPHandler builds the reporting-api/csp handler on BatchReportHandler.
func NewReportAPICSPHandler(filter Filter, opts Options) http.Handler {
	return &BatchReportHandler[ReportAPIReport]{
		HandlerName:  "reporting_api_csp",
		ExpectedType: "csp-violation",
		Options:      opts,

		SetResponseHeaders: setCORSResponseHeaders,

		Validate: func(report ReportAPIReport) *Rejection {
			return filter.validate(report.Body.BlockedURL, report.Body.DocumentURL)
		},

		Process: func(report ReportAPIReport) ProcessResult {
			reportOnly := report.Body.Disposition == "report"
			if opts.TruncateQueryStringFragment {
				report.Body.DocumentURL = truncateQueryStringFragment(report.Body.DocumentURL)
				report.Body.Referrer = truncateQueryStringFragment(report.Body.Referrer)
				report.Body.BlockedURL = truncateQueryStringFragment(report.Body.BlockedURL)
				report.Body.SourceFile = truncateQueryStringFragment(report.Body.SourceFile)
			}

			attrs := make([]slog.Attr, 0, 13+maxRequestAttrs)
			attrs = append(attrs,
				slog.String("blocked_uri", report.Body.BlockedURL),
				slog.Int("column_number", report.Body.ColumnNumber),
				slog.String("disposition", report.Body.Disposition),
				slog.String("document_uri", report.Body.DocumentURL),
				slog.String("effective_directive", report.Body.EffectiveDirective),
				slog.Int("line_number", report.Body.LineNumber),
				slog.String("original_policy", report.Body.OriginalPolicy),
				slog.String("referrer", report.Body.Referrer),
				slog.Bool("report_only", reportOnly),
				slog.String("script_sample", report.Body.Sample),
				slog.String("source_file", report.Body.SourceFile),
				slog.Int("status_code", report.Body.StatusCode),
				slog.String("violated_directive", report.Body.EffectiveDirective),
			)

			return ProcessResult{Attrs: attrs, Mode: modeLabel(reportOnly)}
		},
	}
}

// setCORSResponseHeaders is shared with ReportAPICorsHandler so the
// preflight and the real response agree on what's allowed. Cross-origin
// report uploads never carry credentials, so a wildcard origin is always
// accepted and there's no need to echo the request's Origin back.
func setCORSResponseHeaders(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
}

// ReportAPICorsHandler answers the CORS preflight a browser sends before
// uploading reports to a different origin.
func ReportAPICorsHandler(w http.ResponseWriter, r *http.Request) {
	setCORSResponseHeaders(w, r)

	// Special handling due to bug in Chrome
	// https://bugs.chromium.org/p/chromium/issues/detail?id=1152867
	w.Header().Set("Access-Control-Allow-Methods", cmp.Or(r.Header.Get("Access-Control-Request-Method"), "*"))
	w.Header().Set("Access-Control-Max-Age", "60")
	w.Header().Set("Access-Control-Allow-Headers", cmp.Or(r.Header.Get("Access-Control-Request-Headers"), "*"))
	w.Header().Set("Vary", "Access-Control-Request-Method, Access-Control-Request-Headers")

	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.Header().Set("Server", "go-csp-collector")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
