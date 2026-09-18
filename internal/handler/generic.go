package handler

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	log "github.com/sirupsen/logrus"
)

// ReportTyped lets the handler check a decoded item's Reporting API `type`
// without type-specific code.
type ReportTyped interface {
	ReportType() string
}

// ProcessResult is what Process returns for one successfully decoded report.
type ProcessResult struct {
	Fields log.Fields
	Mode   string // second Prometheus label, e.g. "enforced" / "report_only"
}

// BatchReportHandler is the shared implementation behind every report
// endpoint: method check, resilient per-item decode, validation, metadata,
// client IP, and metrics. Type-specific behavior is supplied via the
// closures below.
type BatchReportHandler[T ReportTyped] struct {
	HandlerName    string
	ExpectedType   string
	MetadataObject bool

	// AllowSingleObject accepts a body that's valid JSON but not a
	// top-level array as a single-item batch instead of a decode error.
	// Needed for CSP's legacy report-uri delivery, which predates the
	// Reporting API and always POSTs one un-batched object. Everything
	// else only ever sends arrays, so this defaults to false.
	//
	// Side effect: an endpoint using this also now accepts a genuine array
	// of several objects, which the old single-object decoder rejected.
	AllowSingleObject bool

	LogClientIP          bool
	LogTruncatedClientIP bool

	Logger  *log.Logger
	Metrics *metrics.Metrics

	// Validate runs once against all decoded items before any are
	// processed; a non-nil error rejects the whole request with 400.
	// reason is the metric label for the rejection cause.
	Validate func(items []T) (reason string, err error)

	// Process turns one decoded, type-matched report into log fields and a
	// metrics mode. Field truncation is the caller's responsibility.
	Process func(report T, r *http.Request, metadata interface{}) ProcessResult

	// RecordSuccessMetric overrides the default
	// Reports.WithLabelValues(HandlerName, mode) increment, for handlers
	// with their own dedicated metric (e.g. NEL's NELReports).
	RecordSuccessMetric func(mode string)

	// RecordValidationErrorMetric overrides the default
	// ReportErrors.WithLabelValues(HandlerName, reason) increment on a
	// Validate rejection, for handlers whose rejection reasons span more
	// than one metric object (e.g. CSP's blocked_uri/blocked_domain vs.
	// validation_error).
	RecordValidationErrorMetric func(reason string)

	// SetResponseHeaders runs first, before the method check, so it
	// applies to every response. Used by reporting-api/csp to set CORS
	// headers on the actual response, not just the OPTIONS preflight.
	SetResponseHeaders func(w http.ResponseWriter, r *http.Request)
}

func (h *BatchReportHandler[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.SetResponseHeaders != nil {
		h.SetResponseHeaders(w, r)
	}

	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		if h.Metrics != nil {
			h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "decode_error").Inc()
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		h.Logger.Debugf("unable to read request body: %s", err)
		return
	}
	defer r.Body.Close()

	var rawItems []json.RawMessage
	if err := json.Unmarshal(body, &rawItems); err != nil {
		var typeErr *json.UnmarshalTypeError
		if h.AllowSingleObject && errors.As(err, &typeErr) {
			// Valid JSON, just not an array - treat it as one item.
			rawItems = []json.RawMessage{json.RawMessage(body)}
		} else {
			if h.Metrics != nil {
				h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "decode_error").Inc()
			}
			w.WriteHeader(http.StatusUnprocessableEntity)
			h.Logger.Debugf("unable to decode invalid JSON payload: %s", err)
			return
		}
	}

	var items []T
	for _, raw := range rawItems {
		var item T
		if err := json.Unmarshal(raw, &item); err != nil {
			if h.Metrics != nil {
				h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "item_decode_error").Inc()
			}
			h.Logger.WithFields(log.Fields{
				"reason": "item_decode_error",
				"body":   string(raw),
				"path":   r.URL.Path,
			}).Warn()
			continue
		}
		items = append(items, item)
	}

	if h.Validate != nil {
		if reason, err := h.Validate(items); err != nil {
			if h.RecordValidationErrorMetric != nil {
				h.RecordValidationErrorMetric(reason)
			} else if h.Metrics != nil {
				h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, reason).Inc()
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			h.Logger.Debugf("received invalid payload: %s", err.Error())
			return
		}
	}

	var metadata interface{}
	if h.MetadataObject {
		metadataMap := make(map[string]string)
		for k, v := range r.URL.Query() {
			metadataMap[k] = v[0]
		}
		metadata = metadataMap
	} else if metadatas, ok := r.URL.Query()["metadata"]; ok {
		metadata = metadatas[0]
	}

	for _, item := range items {
		if h.ExpectedType != "" && item.ReportType() != h.ExpectedType {
			if h.Metrics != nil {
				h.Metrics.ReportIgnored.WithLabelValues(h.HandlerName, "unsupported_type").Inc()
			}
			continue
		}

		result := h.Process(item, r, metadata)

		if h.LogClientIP || h.LogTruncatedClientIP {
			addClientIPField(result.Fields, r, h.LogClientIP, h.LogTruncatedClientIP, h.Logger)
		}

		h.Logger.WithFields(result.Fields).Info()
		if h.RecordSuccessMetric != nil {
			h.RecordSuccessMetric(result.Mode)
		} else if h.Metrics != nil {
			h.Metrics.Reports.WithLabelValues(h.HandlerName, result.Mode).Inc()
		}
	}

	w.WriteHeader(http.StatusOK)
}

func addClientIPField(fields log.Fields, r *http.Request, logFull, logTruncated bool, logger *log.Logger) {
	if logFull {
		ip, err := utils.GetClientIP(r)
		if err != nil {
			logger.Warnf("unable to parse client ip: %s", err)
		} else {
			fields["client_ip"] = ip.String()
		}
	}

	if logTruncated {
		ip, err := utils.GetClientIP(r)
		if err != nil {
			logger.Warnf("unable to parse client ip: %s", err)
		} else {
			fields["client_ip"] = utils.TruncateClientIP(ip)
		}
	}
}
