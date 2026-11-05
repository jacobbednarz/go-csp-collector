package handler

import (
	"fmt"
	"log/slog"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCachedReportMetricsConcurrent(t *testing.T) {
	t.Parallel()
	m := newTestMetrics()
	h := NewReportAPICSPHandler(Filter{}, Options{Logger: slog.New(slog.DiscardHandler), Metrics: m})
	if got := testutil.CollectAndCount(m.Reports); got != 0 {
		t.Fatalf("series at startup = %d, want 0", got)
	}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Go(func() {
			for j := range 20 {
				disposition := "enforce"
				if (i+j)%2 == 0 {
					disposition = "report"
				}
				body := fmt.Sprintf(`[{"type":"csp-violation","body":{"documentURL":"https://example.com/","disposition":%q}}]`, disposition)
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, httptest.NewRequest("POST", "/reporting-api/csp", strings.NewReader(body)))
				if rr.Code != 200 {
					t.Errorf("status = %d, want 200", rr.Code)
				}
			}
		})
	}
	wg.Wait()
	for _, mode := range []string{"enforced", "report_only"} {
		if got := testutil.ToFloat64(m.Reports.WithLabelValues("reporting_api_csp", mode)); got != 320 {
			t.Errorf("%s = %v, want 320", mode, got)
		}
	}
}

func BenchmarkReportSuccessMetric(b *testing.B) {
	m := newTestMetrics()
	record := reportSuccessMetric(m, "csp", "enforced", "report_only")
	record("enforced")
	for _, cached := range []bool{false, true} {
		name := "lookup"
		if cached {
			name = "cached"
		}
		b.Run(name+"/serial", func(b *testing.B) {
			b.ReportAllocs()
			if cached {
				for b.Loop() {
					record("enforced")
				}
			} else {
				for b.Loop() {
					m.Reports.WithLabelValues("csp", "enforced").Inc()
				}
			}
		})
		b.Run(name+"/parallel", func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				if cached {
					for pb.Next() {
						record("enforced")
					}
				} else {
					for pb.Next() {
						m.Reports.WithLabelValues("csp", "enforced").Inc()
					}
				}
			})
		})
	}
}
