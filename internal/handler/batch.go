package handler

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"slices"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
)

// maxBodyBytes caps how much of a request body is read. Chrome queues at most
// 100 reports, and each CSP report repeats the full policy, which header size
// limits keep to roughly 32KB, so a real batch stays near 3MB at most.
const maxBodyBytes = 5 << 20

// ReportTyped lets the handler check a decoded item's Reporting API `type`
// without type-specific code.
type ReportTyped interface {
	ReportType() string
}

// Fields are the key/value pairs logged for one report.
type Fields map[string]any

// attrs returns the fields sorted by key, so every report logs its fields
// in the same order.
func (f Fields) attrs() []slog.Attr {
	keys := make([]string, 0, len(f))
	for k := range f {
		keys = append(keys, k)
	}
	slices.Sort(keys)

	attrs := make([]slog.Attr, 0, len(keys))
	for _, k := range keys {
		attrs = append(attrs, slog.Any(k, f[k]))
	}
	return attrs
}

// ProcessResult is what Process returns for one successfully decoded report.
type ProcessResult struct {
	Fields Fields
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

	// SingleObject decodes the body as exactly one report instead of an
	// array. CSP's report-uri delivery predates the Reporting API and the
	// spec only allows one un-batched object, so arrays are rejected there
	// to match the spec. Any decode failure rejects the whole request,
	// since there's no batch to salvage the rest of.
	SingleObject bool

	LogClientIP          bool
	LogTruncatedClientIP bool

	Logger  *slog.Logger
	Metrics *metrics.Metrics

	// Validate runs against each type-matched report before it's processed.
	// reason is the metric label for the rejection cause. A rejected report
	// in a batch is counted and skipped: the Reporting API treats any
	// non-2xx response as a failed upload, discarding the whole batch and
	// backing off the endpoint, so one filtered report must not cost the
	// rest. In SingleObject mode the report is the request, so a rejection
	// is a 400.
	Validate func(report T) (reason string, err error)

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

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		if h.Metrics != nil {
			h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "body_too_large").Inc()
		}
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		h.Logger.Debug("request body exceeds the size limit", "limit_bytes", maxBodyBytes)
		return
	}
	if err != nil {
		if h.Metrics != nil {
			h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "decode_error").Inc()
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		h.Logger.Debug("unable to read request body", "error", err)
		return
	}
	defer r.Body.Close()

	items, err := h.decode(body, r)
	if err != nil {
		if h.Metrics != nil {
			h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "decode_error").Inc()
		}
		w.WriteHeader(http.StatusUnprocessableEntity)
		h.Logger.Debug("unable to decode invalid JSON payload", "error", err)
		return
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

		if h.Validate != nil {
			if reason, err := h.Validate(item); err != nil {
				if h.RecordValidationErrorMetric != nil {
					h.RecordValidationErrorMetric(reason)
				} else if h.Metrics != nil {
					h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, reason).Inc()
				}
				h.Logger.Debug("received invalid payload", "error", err)
				if h.SingleObject {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				continue
			}
		}

		result := h.Process(item, r, metadata)

		if h.LogClientIP || h.LogTruncatedClientIP {
			addClientIPField(result.Fields, r, h.LogClientIP, h.LogTruncatedClientIP, h.Logger)
		}

		h.Logger.LogAttrs(r.Context(), slog.LevelInfo, "", result.Fields.attrs()...)
		if h.RecordSuccessMetric != nil {
			h.RecordSuccessMetric(result.Mode)
		} else if h.Metrics != nil {
			h.Metrics.Reports.WithLabelValues(h.HandlerName, result.Mode).Inc()
		}
	}

	w.WriteHeader(http.StatusOK)
}

// decode returns an error only when the body as a whole can't be decoded.
// In batch mode a malformed item is counted and skipped, so one bad report
// doesn't drop the well-formed ones sent alongside it.
func (h *BatchReportHandler[T]) decode(body []byte, r *http.Request) ([]T, error) {
	if h.SingleObject {
		var item T
		if err := json.Unmarshal(body, &item); err != nil {
			return nil, err
		}
		return []T{item}, nil
	}

	var rawItems []json.RawMessage
	if err := json.Unmarshal(body, &rawItems); err != nil {
		return nil, err
	}

	var items []T
	for _, raw := range rawItems {
		var item T
		if err := json.Unmarshal(raw, &item); err != nil {
			if h.Metrics != nil {
				h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "item_decode_error").Inc()
			}
			h.Logger.Debug("skipping a report that couldn't be decoded",
				"reason", "item_decode_error",
				"body", string(raw),
				"path", r.URL.Path,
			)
			continue
		}
		items = append(items, item)
	}
	return items, nil
}

// truncateURLFields strips the query string and fragment from each named
// field, for --truncate-query-fragment.
func truncateURLFields(fields Fields, keys ...string) {
	for _, k := range keys {
		if v, ok := fields[k].(string); ok {
			fields[k] = utils.TruncateQueryStringFragment(v)
		}
	}
}

func addClientIPField(fields Fields, r *http.Request, logFull, logTruncated bool, logger *slog.Logger) {
	if logFull {
		ip, err := utils.GetClientIP(r)
		if err != nil {
			logger.Warn("unable to parse client ip", "error", err)
		} else {
			fields["client_ip"] = ip.String()
		}
	}

	if logTruncated {
		ip, err := utils.GetClientIP(r)
		if err != nil {
			logger.Warn("unable to parse client ip", "error", err)
		} else {
			fields["client_ip"] = utils.TruncateClientIP(ip)
		}
	}
}
