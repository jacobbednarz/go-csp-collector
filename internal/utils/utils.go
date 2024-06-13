package utils

import (
	"fmt"
	urlverifier "github.com/davidmytton/url-verifier"
	"net/http"
	"net/netip"
	"strings"
)

func TrimEmptyAndComments(s []string) []string {
	var r []string
	for _, str := range s {
		if str == "" {
			continue
		}

		if strings.HasPrefix(str, "#") {
			continue
		}

		r = append(r, str)
	}
	return r
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
		addr, err := netip.ParseAddr(s)
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

func Ternary(condition bool, trueValue, falseValue string) string {
	if condition {
		return trueValue
	}
	return falseValue
}

func ValidateOrigin(origin string) bool {
	verifier := urlverifier.NewVerifier()
	ret, err := verifier.Verify(origin)

	if err != nil {
		return false
	}
	return ret.IsRFC3986URL
}
