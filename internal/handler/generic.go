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
// This covers every array-based report endpoint (NEL, COOP, COEP, default,
// reporting-api/csp) and, with AllowSingleObject, CSP's legacy report-uri
// endpoint too, which POSTs a single un-batched object rather than an
// array.
type BatchReportHandler[T ReportTyped] struct {
	HandlerName    string
	ExpectedType   string
	MetadataObject bool

	// AllowSingleObject, if set, makes a request body that is valid JSON
	// but not a top-level array get treated as a single-item batch instead
	// of being rejected as a decode error. This exists for CSP's legacy
	// report-uri delivery, which predates the Reporting API and always
	// POSTs exactly one un-batched report per violation
	// (`{"csp-report": {...}}`), never an array. Every other handler in
	// this codebase was specified after the Reporting API existed and only
	// ever receives arrays, so this defaults to false and their existing
	// strict-array behavior (a bare object still 422s) is unchanged.
	//
	// One deliberate side effect: with this set, an endpoint that used to
	// only ever accept a single object will now also accept a genuine JSON
	// array of several objects in one request, processing each as its own
	// report. The old single-object decoder would have rejected that shape
	// outright (a decode error, since a struct can't unmarshal from a JSON
	// array). This is a real, noted behavior change from the original
	// legacy handler, not an oversight.
	AllowSingleObject bool

	LogClientIP          bool
	LogTruncatedClientIP bool

	Logger  *log.Logger
	Metrics *metrics.Metrics

	// Validate, if set, runs once against every successfully decoded item
	// before any of them are processed. Returning a non-nil error rejects
	// the whole request with 400 and logs nothing, matching NEL's existing
	// validateReports behavior. reason is the metric label to increment on
	// rejection, so a handler with more than one rejection cause (CSP's
	// blocked_uri vs blocked_domain vs validation_error, each hitting a
	// different metric) can still be told apart, not just a single
	// "validation_error" for everything. NEL, which only ever has one
	// rejection cause, just always returns "validation_error" here.
	Validate func(items []T) (reason string, err error)

	// Process turns one successfully decoded, type-matched report into log
	// fields and a metrics mode. Truncation, if any, is the caller's
	// responsibility here, since which fields need truncating varies by
	// type (NEL truncates url/referrer, COOP truncates opener_url/
	// referrer/source_file, CSP truncates yet another set).
	Process func(report T, r *http.Request, metadata interface{}) ProcessResult

	// RecordSuccessMetric, if set, is called instead of the default
	// Metrics.Reports.WithLabelValues(HandlerName, mode) increment. This
	// exists because NEL has its own dedicated NELReports metric (labeled
	// only by mode, no handler label), separate from the shared Reports
	// counter CSP and reporting-api/csp use. Without this hook, porting
	// NEL onto this type would silently stop incrementing
	// csp_collector_nel_reports_total and start incrementing a
	// differently-shaped metric instead, a real breaking change for
	// anyone scraping the old name, found only by actually trying the
	// port, not by designing this type up front.
	RecordSuccessMetric func(mode string)

	// RecordValidationErrorMetric works the same way, for the rejection
	// path Validate triggers. Optional; if unset, the default
	// ReportErrors.WithLabelValues(HandlerName, reason) increment is used.
	// reporting-api/csp needs this override for real, not just for
	// consistency: its blocked_uri and blocked_domain rejections
	// increment a completely different metric, ReportFiltered, not
	// ReportErrors with a different label. A single default label choice
	// cannot represent that on its own.
	RecordValidationErrorMetric func(reason string)
}

func (h *BatchReportHandler[T]) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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
			// Valid JSON, just not a top-level array - treat the whole body
			// as a single-item batch rather than rejecting it. A genuinely
			// malformed body (a json.SyntaxError, e.g. non-JSON text) still
			// falls through to the decode_error path below regardless of
			// this flag.
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
			// Shared across every handler that supports it today, unlike
			// truncation this part genuinely doesn't vary by type.
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
