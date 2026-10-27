package handler

import (
	"fmt"
	"net/http"
	"net/netip"
	"strings"
)

// requestClientIP is the address of the client that sent r. Behind a proxy
// that's the first X-Forwarded-For entry, which the client can set to
// anything, so it's only suitable for logging.
func requestClientIP(r *http.Request) (netip.Addr, error) {
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

// truncateClientIP keeps only the network an address belongs to: /24 for
// IPv4 and /64 for IPv6.
func truncateClientIP(addr netip.Addr) string {
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
