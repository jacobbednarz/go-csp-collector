package handler

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	log "github.com/sirupsen/logrus"
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

// NewNELHandler builds a NEL report handler on top of the shared
// BatchReportHandler. reportOnly and truncateQueryStringFragment are
// closed over rather than stored as their own fields on the generic type,
// since they only affect the type-specific Process/Validate callbacks, not
// anything the generic wrapper does itself.
func NewNELHandler(reportOnly, truncateQueryStringFragment, logClientIP, logTruncatedClientIP, metadataObject bool, logger *log.Logger, m *metrics.Metrics) http.Handler {
	return &BatchReportHandler[NELReport]{
		HandlerName:          "nel",
		ExpectedType:         "network-error",
		MetadataObject:       metadataObject,
		LogClientIP:          logClientIP,
		LogTruncatedClientIP: logTruncatedClientIP,
		Logger:               logger,
		Metrics:              m,

		Validate: func(items []NELReport) error {
			for _, report := range items {
				if report.Type != "network-error" {
					continue
				}
				if !strings.HasPrefix(report.URL, "http") {
					return fmt.Errorf("url ('%s') is invalid", report.URL)
				}
			}
			return nil
		},

		Process: func(report NELReport, r *http.Request, metadata interface{}) ProcessResult {
			url := report.URL
			referrer := report.Body.Referrer
			if truncateQueryStringFragment {
				url = utils.TruncateQueryStringFragment(url)
				referrer = utils.TruncateQueryStringFragment(referrer)
			}

			mode := "enforced"
			if reportOnly {
				mode = "report_only"
			}

			return ProcessResult{
				Fields: log.Fields{
					"report_only":       reportOnly,
					"url":               url,
					"referrer":          referrer,
					"type":              report.Body.Type,
					"phase":             report.Body.Phase,
					"protocol":          report.Body.Protocol,
					"method":            report.Body.Method,
					"status_code":       report.Body.StatusCode,
					"elapsed_time":      report.Body.ElapsedTime,
					"server_ip":         report.Body.ServerIP,
					"sampling_fraction": report.Body.SamplingFraction,
					"metadata":          metadata,
					"path":              r.URL.Path,
				},
				Mode: mode,
			}
		},
	}
}
