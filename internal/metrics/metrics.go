package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

const (
	namespace = "csp_collector"
)

type Metrics struct {
	Reports          *prometheus.CounterVec
	NELReports       *prometheus.CounterVec
	ReportFiltered   *prometheus.CounterVec
	ReportIgnored    *prometheus.CounterVec
	ReportErrors     *prometheus.CounterVec
	RequestDuration  *prometheus.HistogramVec
	RequestsInFlight *prometheus.GaugeVec
}

func New(registry *prometheus.Registry) *Metrics {
	m := &Metrics{
		Reports: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "reports_total",
				Help:      "Total number of successfully processed CSP reports.",
			},
			[]string{"handler", "mode"},
		),
		NELReports: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "nel_reports_total",
				Help:      "Total number of successfully processed NEL reports.",
			},
			[]string{"mode"},
		),
		ReportFiltered: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "reports_filtered_total",
				Help:      "Total number of reports filtered by configured rules.",
			},
			[]string{"handler", "reason"},
		),
		ReportIgnored: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "reports_ignored_total",
				Help:      "Total number of reports intentionally ignored.",
			},
			[]string{"handler", "reason"},
		),
		ReportErrors: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Name:      "reports_errors_total",
				Help:      "Total number of reports rejected due to errors.",
			},
			[]string{"handler", "type"},
		),
		RequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: namespace,
				Name:      "http_request_duration_seconds",
				Help:      "HTTP request duration in seconds.",
				Buckets:   prometheus.DefBuckets,
			},
			[]string{"handler", "route", "method", "code"},
		),
		RequestsInFlight: prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Namespace: namespace,
				Name:      "http_requests_in_flight",
				Help:      "Current number of in-flight HTTP requests.",
			},
			[]string{"handler", "route"},
		),
	}

	registry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		m.Reports,
		m.NELReports,
		m.ReportFiltered,
		m.ReportIgnored,
		m.ReportErrors,
		m.RequestDuration,
		m.RequestsInFlight,
	)

	return m
}
