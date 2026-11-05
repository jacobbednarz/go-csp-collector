package handler

import (
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
)

// isBlockedByDomain returns true when the hostname of blockedURI exactly
// matches domain or is a subdomain of domain (e.g. "foo.example.com" matches
// "example.com"). The check is an exact suffix comparison, not fuzzy matching.
// domains must be lowercase without a trailing dot, as parsed at startup.
func isBlockedByDomain(blockedURI string, domains map[string]struct{}) bool {
	if len(domains) == 0 {
		return false
	}

	u, err := url.Parse(blockedURI)
	if err != nil || u.Host == "" {
		return false
	}

	// Hostnames are case-insensitive, and a trailing dot names the same host
	// as a fully qualified name.
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for {
		if _, ok := domains[host]; ok {
			return true
		}
		_, suffix, ok := strings.Cut(host, ".")
		if !ok {
			return false
		}
		host = suffix
	}
}

// Filter drops CSP reports about resources the operator has chosen to
// ignore, such as those injected by browser extensions.
type Filter struct {
	// BlockedURIs are prefixes of the blocked URI to drop.
	BlockedURIs []string

	// BlockedDomains drops blocked URIs on these domains and their
	// subdomains. Each must be lowercase without a trailing dot.
	BlockedDomains []string
}

// validator compiles the domain set once so report processing only checks
// the hostname and its parent domains.
func (f Filter) validator() func(blockedURI, documentURI string) *Rejection {
	domains := make(map[string]struct{}, len(f.BlockedDomains))
	for _, domain := range f.BlockedDomains {
		domains[domain] = struct{}{}
	}
	return func(blockedURI, documentURI string) *Rejection {
		for _, prefix := range f.BlockedURIs {
			if strings.HasPrefix(blockedURI, prefix) {
				return &Rejection{Reason: "blocked_uri", Filtered: true, Err: fmt.Errorf("blocked URI ('%s') is an invalid resource", prefix)}
			}
		}
		if isBlockedByDomain(blockedURI, domains) {
			return &Rejection{Reason: "blocked_domain", Filtered: true, Err: fmt.Errorf("blocked URI ('%s') is an invalid resource", blockedURI)}
		}
		return requireHTTPURL("document URI", documentURI)
	}
}

// CSPReport is the payload delivered by CSP2's report-uri directive: a
// single, un-batched object per violation, never an array.
type CSPReport struct {
	Body CSPReportBody `json:"csp-report"`
}

// ReportType satisfies ReportTyped. Unused: NewCSPHandler leaves
// ExpectedType empty.
func (r CSPReport) ReportType() string { return "csp-violation" }

// CSPReportBody contains the fields that are nested within the
// violation report.
type CSPReportBody struct {
	DocumentURI        string `json:"document-uri"`
	Referrer           string `json:"referrer"`
	BlockedURI         string `json:"blocked-uri"`
	ViolatedDirective  string `json:"violated-directive"`
	EffectiveDirective string `json:"effective-directive"`
	OriginalPolicy     string `json:"original-policy"`
	Disposition        string `json:"disposition"`
	ScriptSample       string `json:"script-sample"`
	StatusCode         any    `json:"status-code"`
	SourceFile         string `json:"source-file"`
	LineNumber         uint32 `json:"line-number"`
	ColumnNumber       uint32 `json:"column-number"`
}

// NewCSPHandler builds the legacy report-uri CSP handler on BatchReportHandler.
func NewCSPHandler(reportOnly bool, filter Filter, opts Options) http.Handler {
	validate := filter.validator()
	return &BatchReportHandler[CSPReport]{
		HandlerName:  "csp",
		SingleObject: true,
		Options:      opts,

		RecordSuccessMetric: reportSuccessMetric(opts.Metrics, "csp", "enforced", "report_only"),

		Validate: func(report CSPReport) *Rejection {
			return validate(report.Body.BlockedURI, report.Body.DocumentURI)
		},

		Process: func(report CSPReport) ProcessResult {
			// The browser knows which header the policy came from, so CSP3's
			// disposition wins over the route. Browsers that omit it fall
			// back to the route the report was sent to.
			reportOnly := reportOnly
			switch report.Body.Disposition {
			case "report":
				reportOnly = true
			case "enforce":
				reportOnly = false
			}

			if opts.TruncateQueryStringFragment {
				report.Body.DocumentURI = truncateQueryStringFragment(report.Body.DocumentURI)
				report.Body.Referrer = truncateQueryStringFragment(report.Body.Referrer)
				report.Body.BlockedURI = truncateQueryStringFragment(report.Body.BlockedURI)
				report.Body.SourceFile = truncateQueryStringFragment(report.Body.SourceFile)
			}

			attrs := make([]slog.Attr, 0, 13+maxRequestAttrs)
			attrs = append(attrs,
				slog.String("blocked_uri", report.Body.BlockedURI),
				slog.Uint64("column_number", uint64(report.Body.ColumnNumber)),
				slog.String("disposition", report.Body.Disposition),
				slog.String("document_uri", report.Body.DocumentURI),
				slog.String("effective_directive", report.Body.EffectiveDirective),
				slog.Uint64("line_number", uint64(report.Body.LineNumber)),
				slog.String("original_policy", report.Body.OriginalPolicy),
				slog.String("referrer", report.Body.Referrer),
				slog.Bool("report_only", reportOnly),
				slog.String("script_sample", report.Body.ScriptSample),
				slog.String("source_file", report.Body.SourceFile),
				slog.Any("status_code", report.Body.StatusCode),
				slog.String("violated_directive", report.Body.ViolatedDirective),
			)

			return ProcessResult{Attrs: attrs, Mode: modeLabel(reportOnly)}
		},
	}
}
