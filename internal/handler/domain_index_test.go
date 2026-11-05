package handler

import (
	"fmt"
	"net/url"
	"strings"
	"testing"
)

func scanBlockedDomains(uri string, domains []string) bool {
	if len(domains) == 0 {
		return false
	}
	u, err := url.Parse(uri)
	if err != nil || u.Host == "" {
		return false
	}
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	for _, domain := range domains {
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func FuzzDomainIndexMatchesScan(f *testing.F) {
	for _, seed := range [][2]string{
		{"https://a.EXAMPLE.com.:443/path", "example.com,other.example"},
		{"https://evilexample.com/path", "example.com"},
		{"https://example.com.evil/path", "example.com"},
		{"https://example..", ""},
		{"https://[::ffff:127.0.0.1]/", "0.1"},
		{"https://[::1]/", "::1"},
		{"https://user:pass@example.com/", "example.com,example.com"},
		{"https://%invalid/", "example.com"},
		{"about:blank", "example.com"},
	} {
		f.Add(seed[0], seed[1])
	}
	f.Fuzz(func(t *testing.T, uri, list string) {
		domains := strings.Split(list, ",")
		index := make(map[string]struct{}, len(domains))
		for _, domain := range domains {
			index[domain] = struct{}{}
		}
		if got, want := isBlockedByDomain(uri, index), scanBlockedDomains(uri, domains); got != want {
			t.Fatalf("indexed match = %v, scan = %v for URI %q and domains %q", got, want, uri, domains)
		}
	})
}

func BenchmarkDomainIndex(b *testing.B) {
	for _, size := range []int{5, 100, 1000} {
		domains := make([]string, size)
		index := make(map[string]struct{}, size)
		for i := range domains {
			domains[i] = fmt.Sprintf("tracker-%d.example", i)
			index[domains[i]] = struct{}{}
		}
		for _, tc := range []struct{ name, uri string }{
			{"miss", "https://legitimate.example.com/path"},
			{"first", "https://sub." + domains[0] + "/path"},
			{"last", "https://sub." + domains[size-1] + "/path"},
		} {
			b.Run(fmt.Sprintf("%d/%s/scan", size, tc.name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					scanBlockedDomains(tc.uri, domains)
				}
			})
			b.Run(fmt.Sprintf("%d/%s/index", size, tc.name), func(b *testing.B) {
				b.ReportAllocs()
				for b.Loop() {
					isBlockedByDomain(tc.uri, index)
				}
			})
		}
	}
}
