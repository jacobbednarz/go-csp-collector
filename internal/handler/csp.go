package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// isBlockedByDomain returns true when the hostname of blockedURI exactly
// matches domain or is a subdomain of domain (e.g. "foo.example.com" matches
// "example.com"). The check is an exact suffix comparison, not fuzzy matching.
// domains must be lowercase without a trailing dot, as parsed at startup.
func isBlockedByDomain(blockedURI string, domains []string) bool {
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
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}

	return false
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

// validate checks a CSP report from either delivery mechanism, which name
// the same fields differently.
func (f Filter) validate(blockedURI, documentURI string) *Rejection {
	for _, prefix := range f.BlockedURIs {
		if strings.HasPrefix(blockedURI, prefix) {
			return &Rejection{Reason: "blocked_uri", Filtered: true, Err: fmt.Errorf("blocked URI ('%s') is an invalid resource", prefix)}
		}
	}
	if isBlockedByDomain(blockedURI, f.BlockedDomains) {
		return &Rejection{Reason: "blocked_domain", Filtered: true, Err: fmt.Errorf("blocked URI ('%s') is an invalid resource", blockedURI)}
	}
	return requireHTTPURL("document URI", documentURI)
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
	return &BatchReportHandler[CSPReport]{
		HandlerName:  "csp",
		SingleObject: true,
		Options:      opts,

		Validate: func(report CSPReport) *Rejection {
			return filter.validate(report.Body.BlockedURI, report.Body.DocumentURI)
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

			lf := Fields{
				"report_only":         reportOnly,
				"document_uri":        report.Body.DocumentURI,
				"referrer":            report.Body.Referrer,
				"blocked_uri":         report.Body.BlockedURI,
				"violated_directive":  report.Body.ViolatedDirective,
				"effective_directive": report.Body.EffectiveDirective,
				"original_policy":     report.Body.OriginalPolicy,
				"disposition":         report.Body.Disposition,
				"script_sample":       report.Body.ScriptSample,
				"status_code":         report.Body.StatusCode,
				"source_file":         report.Body.SourceFile,
				"line_number":         report.Body.LineNumber,
				"column_number":       report.Body.ColumnNumber,
			}

			if opts.TruncateQueryStringFragment {
				truncateURLFields(lf, "document_uri", "referrer", "blocked_uri", "source_file")
			}

			return ProcessResult{Fields: lf, Mode: modeLabel(reportOnly)}
		},
	}
}
