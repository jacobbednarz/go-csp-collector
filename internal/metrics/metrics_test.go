package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewRegistersMetrics(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := New(registry)
	if m == nil {
		t.Fatal("expected metrics instance")
	}

	gathered, err := registry.Gather()
	if err != nil {
		t.Fatalf("failed to gather metrics: %v", err)
	}
	if len(gathered) == 0 {
		t.Fatal("expected registered metrics in registry")
	}
}

func TestCountersIncrement(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := New(registry)

	m.Reports.WithLabelValues("csp", "enforced").Inc()
	m.NELReports.WithLabelValues("report_only").Inc()
	m.ReportFiltered.WithLabelValues("csp", "blocked_uri").Inc()
	m.ReportIgnored.WithLabelValues("nel", "unsupported_type").Inc()
	m.ReportErrors.WithLabelValues("nel", "decode_error").Inc()

	if got := testutil.ToFloat64(m.Reports.WithLabelValues("csp", "enforced")); got != 1 {
		t.Fatalf("reports_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.NELReports.WithLabelValues("report_only")); got != 1 {
		t.Fatalf("nel_reports_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ReportFiltered.WithLabelValues("csp", "blocked_uri")); got != 1 {
		t.Fatalf("reports_filtered_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ReportIgnored.WithLabelValues("nel", "unsupported_type")); got != 1 {
		t.Fatalf("reports_ignored_total = %v, want 1", got)
	}
	if got := testutil.ToFloat64(m.ReportErrors.WithLabelValues("nel", "decode_error")); got != 1 {
		t.Fatalf("reports_errors_total = %v, want 1", got)
	}
}

func TestHistogramObserves(t *testing.T) {
	registry := prometheus.NewRegistry()
	m := New(registry)

	m.RequestDuration.WithLabelValues("csp", "/csp", "POST", "200").Observe(0.125)

	if got := testutil.CollectAndCount(m.RequestDuration); got == 0 {
		t.Fatal("expected histogram samples")
	}
}
