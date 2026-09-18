package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	log "github.com/sirupsen/logrus"
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
func NewReportAPICSPHandler(blockedURIs, blockedDomains []string, truncateQueryStringFragment, logClientIP, logTruncatedClientIP, metadataObject bool, logger *log.Logger, m *metrics.Metrics) http.Handler {
	return &BatchReportHandler[ReportAPIReport]{
		HandlerName:          "reporting_api_csp",
		ExpectedType:         "csp-violation",
		MetadataObject:       metadataObject,
		LogClientIP:          logClientIP,
		LogTruncatedClientIP: logTruncatedClientIP,
		Logger:               logger,
		Metrics:              m,

		SetResponseHeaders: setCORSResponseHeaders,

		Validate: func(items []ReportAPIReport) (string, error) {
			for _, violation := range items {
				if violation.Type != "csp-violation" {
					continue
				}
				for _, value := range blockedURIs {
					if strings.HasPrefix(violation.Body.BlockedURL, value) {
						return "blocked_uri", fmt.Errorf("blocked URI ('%s') is an invalid resource", value)
					}
				}
				if isBlockedByDomain(violation.Body.BlockedURL, blockedDomains) {
					return "blocked_domain", fmt.Errorf("blocked URI ('%s') is an invalid resource", violation.Body.BlockedURL)
				}
				if !strings.HasPrefix(violation.Body.DocumentURL, "http") {
					return "validation_error", fmt.Errorf("document URI ('%s') is invalid", violation.Body.DocumentURL)
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
				m.ReportFiltered.WithLabelValues("reporting_api_csp", "blocked_uri").Inc()
			case "blocked_domain":
				m.ReportFiltered.WithLabelValues("reporting_api_csp", "blocked_domain").Inc()
			default:
				m.ReportErrors.WithLabelValues("reporting_api_csp", "validation_error").Inc()
			}
		},

		Process: func(report ReportAPIReport, r *http.Request, metadata interface{}) ProcessResult {
			reportOnly := report.Body.Disposition == "report"
			lf := log.Fields{
				"report_only":         reportOnly,
				"document_uri":        report.Body.DocumentURL,
				"referrer":            report.Body.Referrer,
				"blocked_uri":         report.Body.BlockedURL,
				"violated_directive":  report.Body.EffectiveDirective,
				"effective_directive": report.Body.EffectiveDirective,
				"original_policy":     report.Body.OriginalPolicy,
				"disposition":         report.Body.Disposition,
				"status_code":         report.Body.StatusCode,
				"source_file":         report.Body.SourceFile,
				"line_number":         report.Body.LineNumber,
				"column_number":       report.Body.ColumnNumber,
				"metadata":            metadata,
				"path":                r.URL.Path,
			}

			if truncateQueryStringFragment {
				lf["document_uri"] = utils.TruncateQueryStringFragment(report.Body.DocumentURL)
				lf["referrer"] = utils.TruncateQueryStringFragment(report.Body.Referrer)
				lf["blocked_uri"] = utils.TruncateQueryStringFragment(report.Body.BlockedURL)
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

// setCORSResponseHeaders is shared with ReportAPICorsHandler so the
// preflight and the real response agree on what's allowed.
func setCORSResponseHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	allow_origin := utils.Ternary(origin != "" && utils.ValidateOrigin(origin), origin, "*")
	w.Header().Set("Access-Control-Allow-Origin", allow_origin)
	w.Header().Set("vary", "Origin")
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
	w.Header().Set("vary", "Origin, Access-Control-Request-Method, Access-Control-Request-Headers")

	w.Header().Set("Cross-Origin-Resource-Policy", "cross-origin")
	w.Header().Set("Content-Type", "text/plain;charset=UTF-8")
	w.Header().Set("Server", "go-csp-collector")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}
