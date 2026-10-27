package handler

import (
	"log/slog"

	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
)

// Options are the settings every report handler shares.
type Options struct {
	// TruncateQueryStringFragment strips the query string and fragment from
	// every logged URL.
	TruncateQueryStringFragment bool

	ClientIP ClientIPMode

	// MetadataObject logs every query parameter of the report URL as an
	// object, instead of only the metadata parameter as a string.
	MetadataObject bool

	Logger  *slog.Logger
	Metrics *metrics.Metrics
}

// ClientIPMode is how much of the reporting client's address is logged.
// It's one setting rather than two flags because both modes write the same
// client_ip field.
type ClientIPMode int

const (
	// ClientIPNone doesn't log the client's address.
	ClientIPNone ClientIPMode = iota

	// ClientIPFull logs the whole address.
	ClientIPFull

	// ClientIPTruncated logs only the network: /24 for IPv4, /64 for IPv6.
	ClientIPTruncated
)
