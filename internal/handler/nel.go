package handler

import (
	"encoding/json"
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

// NELViolationReportHandler handles incoming NEL reports.
type NELViolationReportHandler struct {
	ReportOnly                  bool
	TruncateQueryStringFragment bool

	LogClientIP          bool
	LogTruncatedClientIP bool
	MetadataObject       bool

	Logger  *log.Logger
	Metrics *metrics.Metrics
}

func (h *NELViolationReportHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var reports []NELReport

	err := decoder.Decode(&reports)
	if err != nil {
		if h.Metrics != nil {
			h.Metrics.ReportErrors.WithLabelValues("nel", "decode_error").Inc()
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		h.Logger.Debugf("unable to decode invalid JSON payload: %s", err)
		return
	}

	defer r.Body.Close()

	if err := h.validateReports(reports); err != nil {
		if h.Metrics != nil {
			h.Metrics.ReportErrors.WithLabelValues("nel", "validation_error").Inc()
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		h.Logger.Debugf("received invalid payload: %s", err.Error())
		return
	}

	var metadata interface{}
	if h.MetadataObject {
		metadataMap := make(map[string]string)
		for k, v := range r.URL.Query() {
			metadataMap[k] = v[0]
		}
		metadata = metadataMap
	} else {
		if metadatas, ok := r.URL.Query()["metadata"]; ok {
			metadata = metadatas[0]
		}
	}

	for _, report := range reports {
		if report.Type != "network-error" {
			if h.Metrics != nil {
				h.Metrics.ReportIgnored.WithLabelValues("nel", "unsupported_type").Inc()
			}
			continue
		}

		url := report.URL
		referrer := report.Body.Referrer
		if h.TruncateQueryStringFragment {
			url = utils.TruncateQueryStringFragment(url)
			referrer = utils.TruncateQueryStringFragment(referrer)
		}

		lf := log.Fields{
			"report_only":       h.ReportOnly,
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
		}

		if h.LogClientIP {
			ip, err := utils.GetClientIP(r)
			if err != nil {
				h.Logger.Warnf("unable to parse client ip: %s", err)
			} else {
				lf["client_ip"] = ip.String()
			}
		}

		if h.LogTruncatedClientIP {
			ip, err := utils.GetClientIP(r)
			if err != nil {
				h.Logger.Warnf("unable to parse client ip: %s", err)
			} else {
				lf["client_ip"] = utils.TruncateClientIP(ip)
			}
		}

		h.Logger.WithFields(lf).Info()
		if h.Metrics != nil {
			mode := "enforced"
			if h.ReportOnly {
				mode = "report_only"
			}
			h.Metrics.NELReports.WithLabelValues(mode).Inc()
		}
	}
}

func (h *NELViolationReportHandler) validateReports(reports []NELReport) error {
	for _, report := range reports {
		if report.Type != "network-error" {
			continue
		}
		if !strings.HasPrefix(report.URL, "http") {
			return fmt.Errorf("url ('%s') is invalid", report.URL)
		}
	}
	return nil
}
