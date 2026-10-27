package utils_test

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/jacobbednarz/go-csp-collector/internal/handler"
	"github.com/jacobbednarz/go-csp-collector/internal/metrics"
	"github.com/jacobbednarz/go-csp-collector/internal/utils"
	"github.com/prometheus/client_golang/prometheus"
)

func TestFilterListProcessing(t *testing.T) {
	// Discard the output we create from the calls here.
	log.SetOutput(io.Discard)

	blockList := []string{
		"resource://",
		"",
		"# comment",
		"chrome-extension://",
		"",
	}
	trimmed := utils.TrimEmptyAndComments(blockList)

	if len(trimmed) != 2 {
		t.Errorf("expected filter list length 2; got %v", len(trimmed))
	}
	if trimmed[0] != "resource://" {
		t.Errorf("unexpected list entry; got %v", trimmed[0])
	}
	if trimmed[1] != "chrome-extension://" {
		t.Errorf("unexpected list entry; got %v", trimmed[1])
	}
}

// Filter files saved on Windows, or checked out with CRLF line endings, would
// otherwise leave a trailing \r on every entry so none of them match.
func TestFilterListProcessingTrimsWhitespace(t *testing.T) {
	got := utils.TrimEmptyAndComments(strings.Split("# comment\r\nchrome-extension\r\n  \r\n moz-extension \r\n", "\n"))
	want := []string{"chrome-extension", "moz-extension"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

func TestLogsPath(t *testing.T) {
	var logBuffer bytes.Buffer
	log := slog.New(slog.NewTextHandler(&logBuffer, nil))

	csp := handler.CSPReport{
		Body: handler.CSPReportBody{
			DocumentURI: "http://example.com",
			BlockedURI:  "http://example.com",
		},
	}

	payload, _ := json.Marshal(csp)

	url := "/deep/link"

	request, err := http.NewRequest("POST", url, bytes.NewBuffer(payload))
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}
	recorder := httptest.NewRecorder()

	cspViolationHandler := handler.NewCSPHandler(false, []string{"foo"}, nil, handler.Options{Logger: log, Metrics: metrics.New(prometheus.NewRegistry())})
	cspViolationHandler.ServeHTTP(recorder, request)

	response := recorder.Result()
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		t.Errorf("expected HTTP status %v; got %v", http.StatusOK, response.StatusCode)
	}

	logOut := logBuffer.String()
	if !strings.Contains(logOut, "path=/deep/link") {
		t.Fatalf("Logged result should contain path value in '%s'", logOut)
	}
}

func TestTruncateQueryStringFragment(t *testing.T) {
	t.Parallel()

	cases := []struct {
		original string
		expected string
	}{
		{"http://localhost.com/?test#anchor", "http://localhost.com/"},
		{"http://example.invalid", "http://example.invalid"},
		{"http://example.invalid#a", "http://example.invalid"},
		{"http://example.invalid?a", "http://example.invalid"},
		{"http://example.invalid#b?a", "http://example.invalid"},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.original, func(t *testing.T) {
			t.Parallel()
			actual := utils.TruncateQueryStringFragment(tc.original)
			if actual != tc.expected {
				t.Errorf("truncating '%s' yielded '%s', expected '%s'", tc.original, actual, tc.expected)
			}
		})
	}
}

func TestGetClientIP(t *testing.T) {
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

			got, err := utils.GetClientIP(r)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("GetClientIP() = %v, want an error", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("GetClientIP() error = %v", err)
			}
			if got.String() != tt.want {
				t.Errorf("GetClientIP() = %v, want %v", got, tt.want)
			}
		})
	}
}
