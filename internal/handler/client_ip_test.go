package handler

import (
	"net/http/httptest"
	"net/netip"
	"testing"
)

func TestRequestClientIP(t *testing.T) {
	tests := []struct {
		name         string
		remoteAddr   string
		forwardedFor string
		want         string
		wantErr      bool
	}{
		{name: "remote_addr", remoteAddr: "203.0.113.7:54321", want: "203.0.113.7"},
		{name: "remote_addr_ipv6", remoteAddr: "[2001:db8::1]:54321", want: "2001:db8::1"},
		{name: "forwarded_for_single", remoteAddr: "10.0.0.1:1", forwardedFor: "203.0.113.7", want: "203.0.113.7"},
		// Each proxy appends the address it received from, so the first
		// entry is the original client.
		{name: "forwarded_for_proxy_chain", remoteAddr: "10.0.0.1:1", forwardedFor: "203.0.113.7, 10.0.0.2, 10.0.0.3", want: "203.0.113.7"},
		{name: "forwarded_for_no_spaces", remoteAddr: "10.0.0.1:1", forwardedFor: "203.0.113.7,10.0.0.2", want: "203.0.113.7"},
		{name: "forwarded_for_ipv6", remoteAddr: "10.0.0.1:1", forwardedFor: "2001:db8::1, 10.0.0.2", want: "2001:db8::1"},
		{name: "forwarded_for_invalid", remoteAddr: "10.0.0.1:1", forwardedFor: "unknown, 10.0.0.2", wantErr: true},
		{name: "remote_addr_invalid", remoteAddr: "not-an-address", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.forwardedFor != "" {
				r.Header.Set("X-Forwarded-For", tt.forwardedFor)
			}

			got, err := requestClientIP(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("requestClientIP() = %v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("requestClientIP() error = %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("requestClientIP() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTruncateClientIP(t *testing.T) {
	tests := []struct {
		name string
		addr netip.Addr
		want string
	}{
		{name: "ipv4", addr: netip.MustParseAddr("203.0.113.7"), want: "203.0.113.0/24"},
		{name: "ipv6", addr: netip.MustParseAddr("2001:db8:1:2:3:4:5:6"), want: "2001:db8:1:2::/64"},
		{name: "invalid", addr: netip.Addr{}, want: "unknown-address"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := truncateClientIP(tt.addr); got != tt.want {
				t.Errorf("truncateClientIP(%v) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}
