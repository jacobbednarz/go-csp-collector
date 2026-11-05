package handler

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestReportLogKeyOrder(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		newHandler func(Options) http.Handler
		body       string
	}{
		{"csp", func(o Options) http.Handler { return NewCSPHandler(false, Filter{}, o) }, `{"csp-report":{"document-uri":"https://example.com/?private","blocked-uri":"inline"}}`},
		{"reporting_csp", func(o Options) http.Handler { return NewReportAPICSPHandler(Filter{}, o) }, `[{"type":"csp-violation","body":{"documentURL":"https://example.com/?private"}}]`},
		{"nel", func(o Options) http.Handler { return NewNELHandler(false, o) }, `[{"type":"network-error","url":"https://example.com/?private"}]`},
		{"coop", NewReportAPICOOPHandler, `[{"type":"coop","url":"https://example.com/?private"}]`},
		{"coep", NewReportAPICOEPHandler, `[{"type":"coep","url":"https://example.com/?private"}]`},
		{"default", NewReportAPIDefaultHandler, `[{"type":"deprecation","url":"https://example.com/?private","body":{"message":"deprecated"}}]`},
	} {
		for _, variant := range []struct {
			name     string
			clientIP ClientIPMode
			truncate bool
		}{
			{"default", ClientIPNone, false},
			{"client_ip", ClientIPFull, false},
			{"truncated", ClientIPTruncated, true},
		} {
			t.Run(tc.name+"/"+variant.name, func(t *testing.T) {
				t.Parallel()
				var buf bytes.Buffer
				h := tc.newHandler(Options{
					Logger: slog.New(slog.NewJSONHandler(&buf, nil)), Metrics: newTestMetrics(),
					ClientIP: variant.clientIP, TruncateQueryStringFragment: variant.truncate, MetadataObject: true,
				})
				rr := httptest.NewRecorder()
				h.ServeHTTP(rr, httptest.NewRequest("POST", "/report?env=prod", strings.NewReader(tc.body)))
				if rr.Code != http.StatusOK {
					t.Fatalf("status = %d, want 200", rr.Code)
				}
				dec := json.NewDecoder(&buf)
				if _, err := dec.Token(); err != nil {
					t.Fatal(err)
				}
				var keys []string
				for dec.More() {
					key, err := dec.Token()
					if err != nil {
						t.Fatal(err)
					}
					var value json.RawMessage
					if err := dec.Decode(&value); err != nil {
						t.Fatal(err)
					}
					if key != "time" && key != "level" && key != "msg" {
						keys = append(keys, key.(string))
					}
				}
				if !slices.IsSorted(keys) || len(slices.Compact(slices.Clone(keys))) != len(keys) {
					t.Fatalf("report keys must be unique and alphabetical: %v", keys)
				}
			})
		}
	}
}

func legacyCSPAttrs(r ReportAPIReport, request []slog.Attr) []slog.Attr {
	fields := map[string]any{
		"report_only": r.Body.Disposition == "report", "document_uri": r.Body.DocumentURL,
		"referrer": r.Body.Referrer, "blocked_uri": r.Body.BlockedURL,
		"violated_directive": r.Body.EffectiveDirective, "effective_directive": r.Body.EffectiveDirective,
		"original_policy": r.Body.OriginalPolicy, "disposition": r.Body.Disposition,
		"script_sample": r.Body.Sample, "status_code": r.Body.StatusCode,
		"source_file": r.Body.SourceFile, "line_number": r.Body.LineNumber, "column_number": r.Body.ColumnNumber,
	}
	for _, a := range request {
		fields[a.Key] = a.Value.Any()
	}
	keys := make([]string, 0, len(fields))
	for key := range fields {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	attrs := make([]slog.Attr, 0, len(keys))
	for _, key := range keys {
		attrs = append(attrs, slog.Any(key, fields[key]))
	}
	return attrs
}

func BenchmarkReportLogAttrs(b *testing.B) {
	r := ReportAPIReport{Body: ReportAPIViolation{DocumentURL: "https://example.com/", BlockedURL: "https://cdn.example.com/app.js", OriginalPolicy: "script-src 'self'", Disposition: "enforce", StatusCode: 200}}
	h := NewReportAPICSPHandler(Filter{}, Options{}).(*BatchReportHandler[ReportAPIReport])
	request := []slog.Attr{slog.Any("metadata", nil), slog.String("path", "/reporting-api/csp")}
	if !slices.EqualFunc(h.Process(r).attrs(request), legacyCSPAttrs(r, request), func(a, b slog.Attr) bool { return a.Equal(b) }) {
		b.Fatal("attribute values or order differ")
	}
	for _, format := range []string{"text", "json"} {
		var handler slog.Handler = slog.NewTextHandler(io.Discard, nil)
		if format == "json" {
			handler = slog.NewJSONHandler(io.Discard, nil)
		}
		logger := slog.New(handler)
		b.Run(format+"/map_sorted", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				logger.LogAttrs(context.Background(), slog.LevelInfo, "", legacyCSPAttrs(r, request)...)
			}
		})
		b.Run(format+"/typed_attrs", func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				logger.LogAttrs(context.Background(), slog.LevelInfo, "", h.Process(r).attrs(request)...)
			}
		})
	}
}
