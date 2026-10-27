package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

// freePort returns a port that nothing is listening on.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}

// busyPort returns a port that's held open until the test ends, and the
// error listening on it gives.
func busyPort(t *testing.T, host string) (int, string) {
	t.Helper()
	ln, err := net.Listen("tcp", host+":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	port := ln.Addr().(*net.TCPAddr).Port
	_, err = net.Listen("tcp", fmt.Sprintf("%s:%d", host, port))
	if err == nil {
		t.Fatal("expected a second listener on the same port to fail")
	}
	return port, err.Error()
}

// decodeLogLine decodes the only JSON log line in out, without its
// timestamp, which changes on every run.
func decodeLogLine(t *testing.T, out string) map[string]any {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 1 {
		t.Fatalf("got %d log lines, want 1: %q", len(lines), out)
	}
	var entry map[string]any
	if err := json.Unmarshal([]byte(lines[0]), &entry); err != nil {
		t.Fatalf("log line isn't JSON: %v: %q", err, lines[0])
	}
	delete(entry, "timestamp")
	return entry
}

// Each problem with the configuration stops the collector before it
// listens, with one error on stderr that names the problem.
func TestRunRejectsInvalidConfiguration(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.txt")
	_, missingErr := os.ReadFile(missing)
	busyReports, busyReportsErr := busyPort(t, "")
	busyMetrics, busyMetricsErr := busyPort(t, "127.0.0.1")
	freeReports := freePort(t)

	tests := []struct {
		name string
		args []string
		want map[string]any
	}{
		{
			name: "unexpected_argument",
			args: []string{"/csp_collector", "--port", "1"},
			want: map[string]any{"level": "error", "message": "unexpected argument, only flags are accepted", "argument": "/csp_collector"},
		},
		{
			name: "both_client_ip_flags",
			args: []string{"--log-client-ip", "--log-truncated-client-ip"},
			want: map[string]any{"level": "error", "message": "--log-client-ip and --log-truncated-client-ip can't be combined, pick one"},
		},
		{
			name: "missing_filter_file",
			args: []string{"--filter-file", missing},
			want: map[string]any{"level": "error", "message": "unable to read filter list", "path": missing, "error": missingErr.Error()},
		},
		{
			name: "missing_domain_filter_file",
			args: []string{"--filter-domains-file", missing},
			want: map[string]any{"level": "error", "message": "unable to read domain filter list", "path": missing, "error": missingErr.Error()},
		},
		{
			name: "health_check_path_without_slash",
			args: []string{"--health-check-path", "healthz"},
			want: map[string]any{"level": "error", "message": "invalid --health-check-path, it must start with / and can't contain spaces or braces", "path": "healthz"},
		},
		{
			name: "health_check_path_with_wildcard",
			args: []string{"--health-check-path", "/{x}"},
			want: map[string]any{"level": "error", "message": "invalid --health-check-path, it must start with / and can't contain spaces or braces", "path": "/{x}"},
		},
		{
			name: "unknown_endpoint",
			args: []string{"--endpoints", "csp,nope"},
			want: map[string]any{"level": "error", "message": "invalid --endpoints value", "error": `unknown endpoint "nope", valid endpoints are: ` + strings.Join(endpointGroups, ", ")},
		},
		{
			name: "report_port_in_use",
			args: []string{"--port", strconv.Itoa(busyReports), "--metrics-port", strconv.Itoa(freePort(t))},
			want: map[string]any{"level": "error", "message": "unable to listen for reports", "error": busyReportsErr},
		},
		{
			name: "metrics_port_in_use",
			args: []string{"--port", strconv.Itoa(freeReports), "--metrics-port", strconv.Itoa(busyMetrics)},
			want: map[string]any{"level": "error", "message": "unable to listen for metrics", "error": busyMetricsErr},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(t.Context(), append([]string{"--output-format", "json"}, tt.args...), &stdout, &stderr)

			if got := exitCode(err); got != 1 {
				t.Errorf("exit code = %d, want 1 (error %v)", got, err)
			}
			if got := decodeLogLine(t, stderr.String()); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("stderr = %v, want %v", got, tt.want)
			}
			if stdout.Len() != 0 {
				t.Errorf("expected nothing on stdout, got %q", stdout.String())
			}
		})
	}

	// The report listener is bound first, so it has to be released when
	// the metrics one then fails.
	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", freeReports))
	if err != nil {
		t.Fatalf("report port wasn't released after the metrics listener failed: %v", err)
	}
	_ = ln.Close()
}

func TestRunFlags(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantExitCode int
		wantStdout   string
		wantStderr   string
	}{
		{name: "version", args: []string{"--version"}, wantStdout: "csp-collector (dev)\n"},
		{name: "help", args: []string{"-h"}, wantStderr: "Usage of csp_collector:\n"},
		{name: "unknown_flag", args: []string{"--nope"}, wantExitCode: 2, wantStderr: "flag provided but not defined: -nope\nUsage of csp_collector:\n"},
		{name: "missing_flag_value", args: []string{"--port"}, wantExitCode: 2, wantStderr: "flag needs an argument: -port\nUsage of csp_collector:\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			err := run(t.Context(), tt.args, &stdout, &stderr)

			if got := exitCode(err); got != tt.wantExitCode {
				t.Errorf("exit code = %d, want %d (error %v)", got, tt.wantExitCode, err)
			}
			if stdout.String() != tt.wantStdout {
				t.Errorf("stdout = %q, want %q", stdout.String(), tt.wantStdout)
			}
			// The usage lists every flag, so only its first lines are
			// compared.
			if !strings.HasPrefix(stderr.String(), tt.wantStderr) || (tt.wantStderr == "") != (stderr.Len() == 0) {
				t.Errorf("stderr = %q, want it to start with %q", stderr.String(), tt.wantStderr)
			}
		})
	}
}

// Cancelling the context, as SIGTERM does, stops both servers cleanly and
// releases their ports.
func TestRunServesUntilCancelled(t *testing.T) {
	port, metricsPort := freePort(t), freePort(t)
	ctx, cancel := context.WithCancel(t.Context())

	var stdout, stderr bytes.Buffer
	done := make(chan error, 1)
	go func() {
		done <- run(ctx, []string{"--port", strconv.Itoa(port), "--metrics-port", strconv.Itoa(metricsPort)}, &stdout, &stderr)
	}()

	for _, url := range []string{
		fmt.Sprintf("http://127.0.0.1:%d%s", port, defaultHealthCheckPath),
		fmt.Sprintf("http://127.0.0.1:%d/metrics", metricsPort),
	} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			resp, err := http.Get(url)
			if err == nil {
				_ = resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Fatalf("GET %s = %d, want 200", url, resp.StatusCode)
				}
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("GET %s never succeeded: %v", url, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run() = %v, want nil after cancelling", err)
		}
	case <-time.After(shutdownTimeout + time.Second):
		t.Fatal("run() didn't return after cancelling")
	}
	if stderr.Len() != 0 {
		t.Errorf("expected nothing on stderr, got %q", stderr.String())
	}

	for _, p := range []int{port, metricsPort} {
		ln, err := net.Listen("tcp", fmt.Sprintf(":%d", p))
		if err != nil {
			t.Errorf("port %d wasn't released: %v", p, err)
			continue
		}
		_ = ln.Close()
	}
}

func TestExitCode(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "success", err: nil, want: 0},
		{name: "usage", err: fmt.Errorf("%w: bad flag", errUsage), want: 2},
		{name: "failure", err: errors.New("unable to listen"), want: 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := exitCode(tt.err); got != tt.want {
				t.Errorf("exitCode(%v) = %d, want %d", tt.err, got, tt.want)
			}
		})
	}
}
