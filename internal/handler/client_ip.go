package handler

import (
	"errors"
	"net/http"
	"net/netip"
	"strings"
)

// The errors don't repeat the address they couldn't parse. They're logged
// even when only the truncated address is, and the header holds the full
// one.
var (
	errInvalidForwardedFor = errors.New("the first X-Forwarded-For entry isn't an IP address")
	errInvalidRemoteAddr   = errors.New("the remote address isn't an IP address and port")
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
			return netip.Addr{}, errInvalidForwardedFor
		}

		return normalizeClientIP(addr), nil
	}

	addrp, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}, errInvalidRemoteAddr
	}

	return normalizeClientIP(addrp.Addr()), nil
}

// normalizeClientIP drops an IPv6 zone, which can be any text the sender
// likes, and turns an IPv4-mapped address into IPv4 so it's logged and
// truncated like one.
func normalizeClientIP(addr netip.Addr) netip.Addr {
	return addr.WithZone("").Unmap()
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
