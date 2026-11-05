package handler

import (
	"log/slog"
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
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

// ReportType satisfies ReportTyped.
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
	mode := modeLabel(reportOnly)
	counters := sync.OnceValue(func() [2]prometheus.Counter {
		return [2]prometheus.Counter{
			opts.Metrics.Reports.WithLabelValues("nel", mode),
			opts.Metrics.NELReports.WithLabelValues(mode),
		}
	})
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
		RecordSuccessMetric: func(_ string) {
			counts := counters()
			counts[0].Inc()
			counts[1].Inc()
		},

		Process: func(report NELReport) ProcessResult {
			if opts.TruncateQueryStringFragment {
				report.URL = truncateQueryStringFragment(report.URL)
				report.Body.Referrer = truncateQueryStringFragment(report.Body.Referrer)
			}

			attrs := make([]slog.Attr, 0, 11+maxRequestAttrs)
			attrs = append(attrs,
				slog.Int("elapsed_time", report.Body.ElapsedTime),
				slog.String("method", report.Body.Method),
				slog.String("phase", report.Body.Phase),
				slog.String("protocol", report.Body.Protocol),
				slog.String("referrer", report.Body.Referrer),
				slog.Bool("report_only", reportOnly),
				slog.Float64("sampling_fraction", report.Body.SamplingFraction),
				slog.String("server_ip", report.Body.ServerIP),
				slog.Int("status_code", report.Body.StatusCode),
				slog.String("type", report.Body.Type),
				slog.String("url", report.URL),
			)

			return ProcessResult{Attrs: attrs, Mode: modeLabel(reportOnly)}
		},
	}
}
