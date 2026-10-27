package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
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

// modeLabel is the metrics mode for a report that's either report-only or
// enforced.
func modeLabel(reportOnly bool) string {
	if reportOnly {
		return "report_only"
	}
	return "enforced"
}

// Rejection is why Validate turned a report away.
type Rejection struct {
	// Reason is the metric label for the rejection.
	Reason string

	// Filtered marks a report that matched a configured filter, counted in
	// reports_filtered_total. Anything else is invalid and counted in
	// reports_errors_total.
	Filtered bool

	Err error
}

// requireHTTPURL rejects a report whose URL isn't a web page's, such as
// one sent from a browser extension, as invalid. name describes the URL in
// the error.
func requireHTTPURL(name, url string) *Rejection {
	if strings.HasPrefix(url, "https://") || strings.HasPrefix(url, "http://") {
		return nil
	}
	return &Rejection{Reason: "validation_error", Err: fmt.Errorf("%s ('%s') is invalid", name, url)}
}

// BatchReportHandler is the shared implementation behind every report
// endpoint: method check, resilient per-item decode, validation, metadata,
// client IP, and metrics. Type-specific behavior is supplied via the
// closures below.
type BatchReportHandler[T ReportTyped] struct {
	HandlerName  string
	ExpectedType string

	// SingleObject decodes the body as exactly one report instead of an
	// array. CSP's report-uri delivery predates the Reporting API and the
	// spec only allows one un-batched object, so arrays are rejected there
	// to match the spec. Any decode failure rejects the whole request,
	// since there's no batch to salvage the rest of.
	SingleObject bool

	Options

	// Validate runs against each type-matched report before it's processed,
	// returning nil to accept it. A rejected report
	// in a batch is counted and skipped: the Reporting API treats any
	// non-2xx response as a failed upload, discarding the whole batch and
	// backing off the endpoint, so one filtered report must not cost the
	// rest. In SingleObject mode the report is the request, so a rejection
	// is a 400.
	Validate func(report T) *Rejection

	// Process turns one decoded, type-matched report into log fields and a
	// metrics mode. Field truncation is the caller's responsibility. The
	// fields that come from the request rather than the report (metadata,
	// path and client_ip) are added afterwards.
	Process func(report T) ProcessResult

	// RecordSuccessMetric overrides the default
	// Reports.WithLabelValues(HandlerName, mode) increment, for handlers
	// that also record a metric of their own (e.g. NEL's deprecated
	// NELReports).
	RecordSuccessMetric func(mode string)

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

	items, err := h.decode(http.MaxBytesReader(w, r.Body, maxBodyBytes), r)
	var maxErr *http.MaxBytesError
	if errors.As(err, &maxErr) {
		h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "body_too_large").Inc()
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		h.Logger.Debug("request body exceeds the size limit", "limit_bytes", maxBodyBytes)
		return
	}
	if err != nil {
		h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "decode_error").Inc()
		w.WriteHeader(http.StatusUnprocessableEntity)
		h.Logger.Debug("unable to decode invalid JSON payload", "error", err)
		return
	}

	metadata := h.metadata(r)
	clientIP := h.clientIP(r)

	for _, item := range items {
		if h.ExpectedType != "" && item.ReportType() != h.ExpectedType {
			h.Metrics.ReportIgnored.WithLabelValues(h.HandlerName, "unsupported_type").Inc()
			continue
		}

		if h.Validate != nil {
			if rej := h.Validate(item); rej != nil {
				if rej.Filtered {
					h.Metrics.ReportFiltered.WithLabelValues(h.HandlerName, rej.Reason).Inc()
				} else {
					h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, rej.Reason).Inc()
				}
				h.Logger.Debug("received invalid payload", "error", rej.Err)
				if h.SingleObject {
					http.Error(w, rej.Err.Error(), http.StatusBadRequest)
					return
				}
				continue
			}
		}

		result := h.Process(item)
		result.Fields["metadata"] = metadata
		result.Fields["path"] = r.URL.Path
		if clientIP != "" {
			result.Fields["client_ip"] = clientIP
		}

		h.Logger.LogAttrs(r.Context(), slog.LevelInfo, "", result.Fields.attrs()...)
		if h.RecordSuccessMetric != nil {
			h.RecordSuccessMetric(result.Mode)
		} else {
			h.Metrics.Reports.WithLabelValues(h.HandlerName, result.Mode).Inc()
		}
	}

	w.WriteHeader(http.StatusOK)
}

// decode returns an error only when the body as a whole can't be decoded.
// In batch mode a malformed item is counted and skipped, so one bad report
// doesn't drop the well-formed ones sent alongside it.
//
// The body is decoded as it's read, one report at a time, rather than read
// whole first. A full batch then costs about its own size in memory instead
// of several times it, which matters because the endpoints are public.
// Nothing is logged until the whole body has decoded, so a body that breaks
// partway through is still rejected as a whole.
func (h *BatchReportHandler[T]) decode(body io.Reader, r *http.Request) ([]T, error) {
	dec := json.NewDecoder(body)

	if h.SingleObject {
		var item T
		if err := dec.Decode(&item); err != nil {
			return nil, err
		}
		if err := expectEOF(dec); err != nil {
			return nil, err
		}
		return []T{item}, nil
	}

	if tok, err := dec.Token(); err != nil {
		return nil, err
	} else if tok != json.Delim('[') {
		return nil, fmt.Errorf("expected an array of reports, got %v", tok)
	}

	var items []T
	var raw json.RawMessage
	for dec.More() {
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		var item T
		if err := json.Unmarshal(raw, &item); err != nil {
			h.Metrics.ReportErrors.WithLabelValues(h.HandlerName, "item_decode_error").Inc()
			h.Logger.Debug("skipping a report that couldn't be decoded",
				"reason", "item_decode_error",
				"body", string(raw),
				"path", r.URL.Path,
			)
			continue
		}
		items = append(items, item)
	}

	// The closing bracket.
	if _, err := dec.Token(); err != nil {
		return nil, err
	}
	if err := expectEOF(dec); err != nil {
		return nil, err
	}
	return items, nil
}

// expectEOF rejects anything after the top-level value, which a decoder
// otherwise leaves unread.
func expectEOF(dec *json.Decoder) error {
	tok, err := dec.Token()
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("unexpected %v after the report", tok)
}

// truncateQueryStringFragment strips everything from the first ? or #.
func truncateQueryStringFragment(uri string) string {
	if i := strings.IndexAny(uri, "#?"); i != -1 {
		return uri[:i]
	}
	return uri
}

// truncateURLFields strips the query string and fragment from each named
// field, for --truncate-query-fragment.
func truncateURLFields(fields Fields, keys ...string) {
	for _, k := range keys {
		if v, ok := fields[k].(string); ok {
			fields[k] = truncateQueryStringFragment(v)
		}
	}
}

// metadata is the metadata field logged with every report in r: either
// the metadata query parameter, or every query parameter as an object.
func (h *BatchReportHandler[T]) metadata(r *http.Request) any {
	query := r.URL.Query()
	if h.MetadataObject {
		metadata := make(map[string]string, len(query))
		for k, v := range query {
			metadata[k] = v[0]
		}
		return metadata
	}
	if v, ok := query["metadata"]; ok {
		return v[0]
	}
	return nil
}

// clientIP is the client_ip field logged with every report in r, or empty
// when it isn't logged. It's worked out once per request, so an address
// that can't be parsed is warned about once rather than for every report
// in the batch.
func (h *BatchReportHandler[T]) clientIP(r *http.Request) string {
	if h.ClientIP == ClientIPNone {
		return ""
	}
	ip, err := requestClientIP(r)
	if err != nil {
		h.Logger.Warn("unable to parse client ip", "error", err)
		return ""
	}
	if h.ClientIP == ClientIPTruncated {
		return truncateClientIP(ip)
	}
	return ip.String()
}
