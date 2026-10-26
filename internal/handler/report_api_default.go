package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	log "github.com/sirupsen/logrus"
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
func NewReportAPIDefaultHandler(truncateQueryStringFragment, logClientIP, logTruncatedClientIP, metadataObject bool, logger *log.Logger, m *metrics.Metrics) http.Handler {
	return &BatchReportHandler[DefaultReport]{
		HandlerName:          "reporting_api_default",
		MetadataObject:       metadataObject,
		LogClientIP:          logClientIP,
		LogTruncatedClientIP: logTruncatedClientIP,
		Logger:               logger,
		Metrics:              m,

		SetResponseHeaders: setCORSResponseHeaders,

		Validate: func(report DefaultReport) (string, error) {
			if !strings.HasPrefix(report.URL, "http") {
				return "validation_error", fmt.Errorf("url ('%s') is invalid", report.URL)
			}
			return "", nil
		},

		Process: func(report DefaultReport, r *http.Request, metadata interface{}) ProcessResult {
			lf := log.Fields{
				"type":     report.Type,
				"url":      report.URL,
				"metadata": metadata,
				"path":     r.URL.Path,
			}

			// URLs inside a body of unknown shape can't be found reliably,
			// so truncation leaves the body out rather than log URLs the
			// operator asked to have stripped.
			if truncateQueryStringFragment {
				truncateURLFields(lf, "url")
			} else {
				lf["body"] = string(report.Body)
			}

			mode := "reporting-api-default"
			if slices.Contains(knownReportTypes, report.Type) {
				mode = report.Type
			}

			return ProcessResult{Fields: lf, Mode: mode}
		},
	}
}
