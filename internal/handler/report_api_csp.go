package handler

import (
	"net/http"

	"github.com/jacobbednarz/go-csp-collector/internal/utils"
)

type ReportAPIReport struct {
	Age       int                `json:"age"`
	Body      ReportAPIViolation `json:"body"`
	Type      string             `json:"type"`
	URL       string             `json:"url"`
	UserAgent string             `json:"user_agent"`
}

func (r ReportAPIReport) ReportType() string { return r.Type }

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
			lf := Fields{
				"report_only":         reportOnly,
				"document_uri":        report.Body.DocumentURL,
				"referrer":            report.Body.Referrer,
				"blocked_uri":         report.Body.BlockedURL,
				"violated_directive":  report.Body.EffectiveDirective,
				"effective_directive": report.Body.EffectiveDirective,
				"original_policy":     report.Body.OriginalPolicy,
				"disposition":         report.Body.Disposition,
				"script_sample":       report.Body.Sample,
				"status_code":         report.Body.StatusCode,
				"source_file":         report.Body.SourceFile,
				"line_number":         report.Body.LineNumber,
				"column_number":       report.Body.ColumnNumber,
			}

			if opts.TruncateQueryStringFragment {
				truncateURLFields(lf, "document_uri", "referrer", "blocked_uri", "source_file")
			}

			return ProcessResult{Fields: lf, Mode: modeLabel(reportOnly)}
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

func ReportAPICorsHandler(w http.ResponseWriter, r *http.Request) {
	setCORSResponseHeaders(w, r)

	method := r.Header.Get("Access-Control-Request-Method")
	header := r.Header.Get("Access-Control-Request-Headers")
	allow_method := utils.Ternary(method != "", method, "*")
	allow_header := utils.Ternary(header != "", header, "*")
	// Special handling due to bug in Chrome
	// https://bugs.chromium.org/p/chromium/issues/detail?id=1152867
	w.Header().Set("Access-Control-Allow-Methods", allow_method)
	w.Header().Set("Access-Control-Max-Age", "60")
	w.Header().Set("Access-Control-Allow-Headers", allow_header)
	w.Header().Set("Vary", "Access-Control-Request-Method, Access-Control-Request-Headers")

	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.Header().Set("Server", "go-csp-collector")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
