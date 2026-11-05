package handler

import (
	"sync"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/prometheus/client_golang/prometheus"
)

// reportSuccessMetric caches the bounded mode counters. Bind them lazily so
// unused modes do not appear as new zero-valued series at startup.
func reportSuccessMetric(m *metrics.Metrics, handlerName string, modes ...string) func(string) {
	counters := make(map[string]func() prometheus.Counter, len(modes))
	for _, mode := range modes {
		counters[mode] = sync.OnceValue(func() prometheus.Counter {
			return m.Reports.WithLabelValues(handlerName, mode)
		})
	}
	return func(mode string) { counters[mode]().Inc() }
}
