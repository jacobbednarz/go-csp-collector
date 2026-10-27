package handler

import (
	"net/http"
)

// NELReport is the structure of a single NEL report as delivered by the
// Reporting API (https://www.w3.org/TR/network-error-logging/).
type NELReport struct {
	Age       int           `json:"age"`
	Body      NELReportBody `json:"body"`
	Type      string        `json:"type"`
	URL       string        `json:"url"`
	UserAgent string        `json:"user_agent"`
}

func (r NELReport) ReportType() string { return r.Type }

// NELReportBody contains the fields nested within each NEL report.
type NELReportBody struct {
	ElapsedTime      int     `json:"elapsed_time"`
	Method           string  `json:"method"`
	Phase            string  `json:"phase"`
	Protocol         string  `json:"protocol"`
	Referrer         string  `json:"referrer"`
	SamplingFraction float64 `json:"sampling_fraction"`
	ServerIP         string  `json:"server_ip"`
	StatusCode       int     `json:"status_code"`
	Type             string  `json:"type"`
}

// NewNELHandler builds a NEL report handler on BatchReportHandler.
func NewNELHandler(reportOnly bool, opts Options) http.Handler {
	return &BatchReportHandler[NELReport]{
		HandlerName:  "nel",
		ExpectedType: "network-error",
		Options:      opts,

		SetResponseHeaders: setCORSResponseHeaders,

		Validate: func(report NELReport) *Rejection {
			return requireHTTPURL("url", report.URL)
		},

		// NEL also counts in its own nel_reports_total, which is deprecated
		// and kept until dashboards have moved to reports_total.
		RecordSuccessMetric: func(mode string) {
			opts.Metrics.Reports.WithLabelValues("nel", mode).Inc()
			opts.Metrics.NELReports.WithLabelValues(mode).Inc()
		},

		Process: func(report NELReport) ProcessResult {
			lf := Fields{
				"report_only":       reportOnly,
				"url":               report.URL,
				"referrer":          report.Body.Referrer,
				"type":              report.Body.Type,
				"phase":             report.Body.Phase,
				"protocol":          report.Body.Protocol,
				"method":            report.Body.Method,
				"status_code":       report.Body.StatusCode,
				"elapsed_time":      report.Body.ElapsedTime,
				"server_ip":         report.Body.ServerIP,
				"sampling_fraction": report.Body.SamplingFraction,
			}

			if opts.TruncateQueryStringFragment {
				truncateURLFields(lf, "url", "referrer")
			}

			return ProcessResult{Fields: lf, Mode: modeLabel(reportOnly)}
		},
	}
}
