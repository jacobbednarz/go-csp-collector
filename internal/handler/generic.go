package handler

import (
	"encoding/json"
	"net/http"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	log "github.com/sirupsen/logrus"
)

// ReportTyped is implemented by any report struct that can report its own
// Reporting API `type` field, so the generic handler can decide whether to
// process or skip an item without needing type-specific code.
type ReportTyped interface {
	ReportType() string
}

// ProcessResult is what a type-specific Process function returns for one
// successfully decoded report.
type ProcessResult struct {
	Fields log.Fields
	// Mode is the second Prometheus label for a successfully processed
	// report (e.g. "enforced" / "report_only"). Handlers that don't have
	// this concept (default.go's catch-all) can put whatever they want
	// here, such as the report's own type.
	Mode string
}

// BatchReportHandler provides the boilerplate shared by every array-based,
// per-item report endpoint: method check, resilient per-item decode
// (matching the #172 fix), metadata handling, client IP logging, and
// metrics. Only the type-specific field extraction is supplied by the
// caller.
//
// This covers NEL's shape and the shape used by coop.go/coep.go/default.go.
// It does NOT cover the legacy CSPViolationReportHandler (decodes a single
// object, not an array) or ReportAPIViolationReportHandler's
// blocked-URI/domain validation (rejects the whole batch before logging
// anything, a fundamentally different control flow). Explored and
// deliberately not folded in here, see docs/experiment-notes.md.
type BatchReportHandler[T ReportTyped] struct {
	HandlerName    string
	ExpectedType   string
	MetadataObject bool

	LogClientIP          bool
	LogTruncatedClientIP bool

	Logger  *log.Logger
	Metrics *metrics.Metrics

	// Validate, if set, runs once against every successfully decoded item
	// before any of them are processed. Returning an error rejects the
	// whole request with 400 and logs nothing, matching NEL's existing
	// validateReports behavior (e.g. rejecting a batch containing a
	// non-http URL). This was not part of the first version of this type;
	// it turned out to be needed once NEL was actually ported onto it,
	// since NEL already had this exact whole-batch-reject behavior
	// alongside its per-item type skip, not just the per-item skip alone.
	Validate func(items []T) error

	// Process turns one successfully decoded, type-matched report into log
	// fields and a metrics mode. Truncation, if any, is the caller's
	// responsibility here, since which fields need truncating varies by
	// type (NEL truncates url/referrer, COOP truncates opener_url/
	// referrer/source_file, CSP truncates yet another set).
	Process func(report T, r *http.Request, metadata interface{}) ProcessResult
}

func (h *BatchReportHandler[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	decoder := json.NewDecoder(r.Body)
	var rawItems []json.RawMessage

	if err := decoder.Decode(&rawItems); err != nil {
		if h.Metrics != nil {
			h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "decode_error").Inc()
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		h.Logger.Debugf("unable to decode invalid JSON payload: %s", err)
		return
	}
	defer r.Body.Close()

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
		if err := h.Validate(items); err != nil {
			if h.Metrics != nil {
				h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "validation_error").Inc()
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
			// Shared across every handler that supports it today, unlike
			// truncation this part genuinely doesn't vary by type.
			addClientIPField(result.Fields, r, h.LogClientIP, h.LogTruncatedClientIP, h.Logger)
		}

		h.Logger.WithFields(result.Fields).Info()
		if h.Metrics != nil {
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
