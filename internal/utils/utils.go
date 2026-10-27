package utils

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// ParseFilterList returns the entries of a filter file, one per line,
// skipping blank lines and # comments.
func ParseFilterList(content string) []string {
	var entries []string
	for line := range strings.Lines(content) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		entries = append(entries, line)
	}
	return entries
}

func TruncateQueryStringFragment(uri string) string {
	idx := strings.IndexAny(uri, "#?")
	if idx != -1 {
		return uri[:idx]
	}

	return uri
}

func TruncateClientIP(addr netip.Addr) string {
	// Ignoring the error is statically safe, as there are always enough bits.
	if addr.Is4() {
		p, _ := addr.Prefix(24)
		return p.String()
	}

	if addr.Is6() {
		p, _ := addr.Prefix(64)
		return p.String()
	}

	return "unknown-address"
}

func GetClientIP(r *http.Request) (netip.Addr, error) {
	if s := r.Header.Get("X-Forwarded-For"); s != "" {
		// Each proxy appends the address it received the request from, so
		// the first entry is the original client.
		client, _, _ := strings.Cut(s, ",")
		addr, err := netip.ParseAddr(strings.TrimSpace(client))
		if err != nil {
			return netip.Addr{}, fmt.Errorf("unable to parse address from X-Forwarded-For=%s: %w", s, err)
		}

		return addr, nil
	}

	addrp, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("unable to parse remote address %s: %w", r.RemoteAddr, err)
	}

	return addrp.Addr(), nil
}
