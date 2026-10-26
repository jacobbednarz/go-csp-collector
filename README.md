# go-csp-collector

A self-hosted collector for the security reports browsers send: Content
Security Policy (CSP) violations, Network Error Logging (NEL), and
Cross-Origin-Opener-Policy (COOP), Cross-Origin-Embedder-Policy (COEP) and
other [Reporting API](https://www.w3.org/TR/reporting-1/) reports. Point your
`report-uri`, `report-to` or `Reporting-Endpoints` headers at it, and each
report is written to stdout as a log line for your log aggregation tool to
pick up. Prometheus metrics are exported alongside.

It also drops unactionable CSP reports, such as those caused by browser
extensions, out of the box. The [default list][1] shows what's ignored.

| Report               | Header that sends it                                         | Route                                              |
| -------------------- | ------------------------------------------------------------ | -------------------------------------------------- |
| [CSP](#csp)          | `Content-Security-Policy` (and `-Report-Only`)               | `/csp`, `/csp/report-only` or `/reporting-api/csp` |
| [NEL](#nel)          | `NEL`                                                        | `/nel` or `/nel/report-only`                       |
| [COOP](#coop)        | `Cross-Origin-Opener-Policy` (and `-Report-Only`)            | `/reporting-api/coop`                              |
| [COEP](#coep)        | `Cross-Origin-Embedder-Policy` (and `-Report-Only`)          | `/reporting-api/coep`                              |
| [Anything else](#default-reporting-api-endpoint) | `Reporting-Endpoints` with a `default` endpoint | `/reporting-api/default`                  |

## Quick start

Run the collector from Docker Hub:

```sh
docker run -p 8080:8080 jacobbednarz/go-csp-collector
```

Then point a policy at it from the site you want reports for:

```http
Reporting-Endpoints: csp-endpoint="https://collector.example.com/reporting-api/csp"
Content-Security-Policy: default-src 'self'; report-uri https://collector.example.com/csp; report-to csp-endpoint
```

Reports show up on the collector's stdout as they arrive.

## Installation

- **Docker**: `jacobbednarz/go-csp-collector` on Docker Hub. Flags go
  straight after the image name, e.g. `docker run -p 8080:8080
  jacobbednarz/go-csp-collector --output-format json`.
- **Binaries**: download one from the [release page][2].
- **From source**: `go install github.com/jacobbednarz/go-csp-collector@latest`,
  which installs a binary named `go-csp-collector`.
- **Kubernetes**: use the [Helm chart][3].
- **systemd**: use the [example unit file][4].

To build it yourself:

```sh
go build -o csp_collector main.go
./csp_collector
```

The collector listens on port 8080 for reports and serves metrics on
`127.0.0.1:9090`.

## Reports

Every logged report includes `metadata` (see [Request
metadata](#request-metadata)) and `path`, the collector route that received
it. The Reporting API routes (`/reporting-api/*` and `/nel*`) also answer CORS
preflight `OPTIONS` requests, which browsers send when the collector is on a
different origin to the reporting site.

### CSP

The collector accepts both ways browsers deliver CSP violations:

- `POST /csp` and `POST /csp/report-only` take the single JSON object sent by
  the `report-uri` directive. `POST /` does the same as `/csp`, but `/csp` is
  recommended.
- `POST /reporting-api/csp` takes the JSON array sent by the `report-to`
  directive through the [Reporting API](https://www.w3.org/TR/reporting-1/)
  ([MDN](https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API)).
  Entries with any other `type` are skipped.

Set both directives so that browsers which only support one of them still
report. Browsers that support `report-to` ignore `report-uri`.

```http
Reporting-Endpoints: csp-endpoint="https://collector.example.com/reporting-api/csp"
Content-Security-Policy: default-src 'self'; report-uri https://collector.example.com/csp; report-to csp-endpoint
```

Each logged CSP report includes the following fields, whichever route it came
in on:

| Field                 | Description                                                                                         |
| --------------------- | --------------------------------------------------------------------------------------------------- |
| `report_only`         | `true` for a report-only policy (see [Report-only policies](#report-only-policies))                  |
| `document_uri`        | The URL of the document the violation happened in                                                  |
| `referrer`            | The document's referrer                                                                             |
| `blocked_uri`         | The URL of the blocked resource, or a keyword such as `inline` or `eval`                            |
| `violated_directive`  | The directive that was violated. On `/reporting-api/csp` this is the same as `effective_directive` |
| `effective_directive` | The directive whose enforcement caused the violation, e.g. `script-src-elem`                        |
| `original_policy`     | The full policy the violation was reported against                                                 |
| `disposition`         | `enforce` or `report`                                                                               |
| `script_sample`       | The first 40 characters of the inline script, event handler or style, if the policy asks for samples |
| `status_code`         | The HTTP status code of the document                                                                |
| `source_file`         | The script that caused the violation                                                                |
| `line_number`         | Line of the violation in `source_file`                                                              |
| `column_number`       | Column of the violation in `source_file`                                                            |

The [filter lists](#filtering-csp-reports) apply to every CSP route.

### NEL

> [!IMPORTANT]
> Network error logging is still experimental in most browsers. This functionality is best effort and may need to adjust as the specification does.

- `POST /nel`: accepts NEL reports for an enforced NEL policy.
- `POST /nel/report-only`: same as `/nel`, but logs `report_only=true`. Useful
  when testing a NEL policy before enforcing it.

NEL reports are delivered by the browser via the Reporting API as a JSON
array. Each entry with `"type": "network-error"` is logged; other types in a
mixed batch are skipped.

To enable NEL reporting, send the `NEL` and `Report-To` (or
`Reporting-Endpoints`) headers from your server:

```http
Reporting-Endpoints: nel-endpoint="https://collector.example.com/nel"
NEL: {"report_to": "nel-endpoint", "max_age": 31536000}
```

Each logged NEL report includes the following fields:

| Field               | Description                                                              |
| ------------------- | ------------------------------------------------------------------------ |
| `report_only`       | `true` when received on the `/nel/report-only` endpoint                  |
| `url`               | The URL of the request that failed                                       |
| `referrer`          | The referrer at the time of the request                                  |
| `type`              | Error type (e.g. `tcp.refused`, `dns.unreachable`, `ok`)                 |
| `phase`             | Phase of the request: `dns`, `connection`, `application`, or `abandoned` |
| `protocol`          | Network protocol (e.g. `h2`, `http/1.1`)                                 |
| `method`            | HTTP method (e.g. `GET`, `POST`)                                         |
| `status_code`       | HTTP status code (0 if the connection never completed)                   |
| `elapsed_time`      | Duration of the request in milliseconds                                  |
| `server_ip`         | IP address of the server that handled the request                        |
| `sampling_fraction` | Fraction of matching requests that were reported                         |

### COOP

`POST /reporting-api/coop` accepts [Cross-Origin-Opener-Policy violation
reports](https://html.spec.whatwg.org/multipage/browsers.html#coop-reporting)
delivered by the Reporting API. Entries with any other `type` are skipped.

COOP reports are sent by Chrome and Safari. Point the `report-to` parameter of
`Cross-Origin-Opener-Policy` (or `Cross-Origin-Opener-Policy-Report-Only`) at
an endpoint for this route:

```http
Reporting-Endpoints: coop-endpoint="https://collector.example.com/reporting-api/coop"
Cross-Origin-Opener-Policy: same-origin; report-to="coop-endpoint"
```

Each logged COOP report includes:

| Field                   | Description                                                                                   |
| ----------------------- | --------------------------------------------------------------------------------------------- |
| `report_only`           | `true` when `disposition` is `reporting`                                                      |
| `url`                   | The URL of the document that generated the report                                             |
| `type`                  | `navigation-to-response`, `navigation-from-response`, or one of the access types listed below |
| `disposition`           | `enforce` or `reporting`                                                                      |
| `effective_policy`      | The COOP value in effect, e.g. `same-origin`                                                  |
| `previous_response_url` | Navigation reports: the response navigated away from                                          |
| `next_response_url`     | Navigation reports: the response navigated to                                                 |
| `referrer`              | The referrer, where the report includes one                                                   |
| `property`              | Access reports: the window property accessed, e.g. `postMessage`                              |
| `opener_url`            | Access reports: the opener's URL                                                              |
| `openee_url`            | Access reports: the opened popup's URL                                                        |
| `initial_popup_url`     | Access reports: the URL the popup was first opened with                                       |
| `other_document_url`    | Access reports: the other document's URL                                                      |
| `source_file`           | Access reports: the script that made the access                                               |
| `line_number`           | Access reports: line of the access in `source_file`                                           |
| `column_number`         | Access reports: column of the access in `source_file`                                         |

Access reports have one of six types, naming which side made the access:
`access-from-coop-page-to-openee`, `access-from-coop-page-to-opener`,
`access-from-coop-page-to-other`, `access-to-coop-page-from-openee`,
`access-to-coop-page-from-opener` and `access-to-coop-page-from-other`.
Fields that don't apply to a report's `type` are logged empty.

### COEP

`POST /reporting-api/coep` accepts [Cross-Origin-Embedder-Policy violation
reports](https://developer.mozilla.org/en-US/docs/Web/API/COEPViolationReport)
delivered by the Reporting API. Entries with any other `type` are skipped.

COEP reports are sent by Chrome and Safari. Like COOP, point the `report-to`
parameter of `Cross-Origin-Embedder-Policy` (or
`Cross-Origin-Embedder-Policy-Report-Only`) at an endpoint for this route:

```http
Reporting-Endpoints: coep-endpoint="https://collector.example.com/reporting-api/coep"
Cross-Origin-Embedder-Policy: require-corp; report-to="coep-endpoint"
```

Each logged COEP report includes:

| Field         | Description                                                      |
| ------------- | ---------------------------------------------------------------- |
| `report_only` | `true` when `disposition` is `reporting`                         |
| `url`         | The URL of the document that generated the report                |
| `type`        | `corp`, `navigation` or `worker initialization`                  |
| `blocked_uri` | The URL of the blocked resource                                  |
| `destination` | `corp` reports: the blocked resource's destination, e.g. `image` |
| `disposition` | `enforce` or `reporting`                                         |

### Default Reporting API endpoint

`POST /reporting-api/default` accepts reports of any type delivered by the
Reporting API.

Browsers send some report types to the endpoint named `default` without any
extra header, such as `deprecation` and `intervention` reports. Others, such as
`permissions-policy-violation`, fall back to it when their header doesn't name
an endpoint. Point `default` at this route to collect them:

```http
Reporting-Endpoints: default="https://collector.example.com/reporting-api/default"
```

The body's shape depends on the report type, so it's logged as raw JSON rather
than split into fields. Each logged report includes:

| Field  | Description                                                                                                                       |
| ------ | --------------------------------------------------------------------------------------------------------------------------------- |
| `type` | The report type, e.g. `deprecation`                                                                                               |
| `url`  | The URL of the document that generated the report                                                                                 |
| `body` | The report body as raw JSON. Left out when `--truncate-query-fragment` is set, since URLs inside it can't be reliably stripped |

### Report-only policies

Every report says whether it came from an enforced or a report-only policy, as
the `report_only` field and the `mode` label on the metrics. That lets you
keep both in one collector and tell them apart in your log aggregation tool.

- **CSP** uses the report's `disposition` (`enforce` or `report`), since the
  browser knows which header the policy came from. `/csp/report-only` is only
  used as a fallback when a browser leaves `disposition` out.
- **NEL** has no disposition, so it's taken from the route: reports sent to
  `/nel/report-only` are report-only.
- **COOP** and **COEP** use the report's `disposition` (`enforce` or
  `reporting`), so they have no report-only routes.

## Configuration

| Flag                        | Description                                                                                                                                         |
| --------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| `--version`                 | Shows the version string before exiting                                                                                                             |
| `--debug`                   | Runs in debug mode producing more verbose output                                                                                                    |
| `--port`                    | Port to listen on for reports, default `8080`                                                                                                       |
| `--metrics-port`            | Port for the Prometheus metrics endpoint, default `9090`                                                                                            |
| `--metrics-bind-addr`       | Bind address for the Prometheus metrics endpoint, default `127.0.0.1`                                                                               |
| `--health-check-path`       | Path for health checkers to use, default `/_healthcheck`                                                                                            |
| `--endpoints`               | Comma separated list of endpoint groups to serve, default all of them. See [Disabling endpoints](#disabling-endpoints)                              |
| `--output-format`           | `text` (default) or `json`. See [Output formats](#output-formats)                                                                                   |
| `--filter-file`             | Replaces the built-in CSP blocked URI prefix list with the one in this file. See [Filtering CSP reports](#filtering-csp-reports)                     |
| `--filter-domains-file`     | Drops CSP reports whose blocked URI is on a domain in this file. See [Filtering CSP reports](#filtering-csp-reports)                                |
| `--truncate-query-fragment` | Removes query strings and fragments from the URLs in each report before logging, to reduce the chance of logging sensitive data                     |
| `--log-client-ip`           | Logs the IP delivering the report, or the first address in `X-Forwarded-For` if present. The header is trusted as sent, so only use it behind a proxy that sets it |
| `--log-truncated-client-ip` | Same as `--log-client-ip`, but truncated to a /24 for IPv4 or a /64 for IPv6. Can't be combined with `--log-client-ip` |
| `--query-params-metadata`   | Logs every query parameter of the report URL as a map in `metadata`. See [Request metadata](#request-metadata)                                      |

### Disabling endpoints

All endpoints are enabled by default. If you don't use one, turn it off with
`--endpoints`, which takes a comma separated list of the endpoint groups to
serve. Any group left out has its routes removed entirely, so requests to them
get a 404 like any other unknown path.

| Group                   | Routes                                                 |
| ----------------------- | ------------------------------------------------------ |
| `csp`                   | `POST /`, `POST /csp`, `POST /csp/report-only`         |
| `reporting-api-csp`     | `OPTIONS` and `POST /reporting-api/csp`                |
| `nel`                   | `OPTIONS` and `POST` for `/nel` and `/nel/report-only` |
| `reporting-api-coop`    | `OPTIONS` and `POST /reporting-api/coop`               |
| `reporting-api-coep`    | `OPTIONS` and `POST /reporting-api/coep`               |
| `reporting-api-default` | `OPTIONS` and `POST /reporting-api/default`            |

For example, to collect CSP reports but not NEL reports:

```sh
csp_collector --endpoints csp,reporting-api-csp
```

The collector refuses to start if the list names an unknown group or is empty,
so a typo can't quietly switch an endpoint off. The health check is always
served.

### Filtering CSP reports

Browser extensions inject scripts and styles that trip CSP, filling the logs
with reports you can't act on. The collector drops CSP reports whose blocked
URI starts with a prefix on its [built-in list][1]. To use your own list
instead, pass `--filter-file` with one prefix per line. It replaces the
built-in list rather than adding to it, so copy `sample.filterlist.txt` as a
starting point.

`--filter-domains-file` drops reports whose blocked URI is on a listed domain
or any subdomain of it. Each line is a bare domain, so `kaspersky-labs.com`
also matches `gc.kis.v2.scr.kaspersky-labs.com`. See `sample.domainlist.txt`
for an example. Each check parses the blocked URI to get its hostname, which
costs roughly 20–35 times more than a prefix check (~180 ns/op against ~5–8
ns/op). For high-throughput deployments, prefer `--filter-file` and only use
domains where you need subdomain matching.

Both lists apply only to the CSP routes. Filtered reports are counted in
`csp_collector_reports_filtered_total`.

### Request metadata

Additional information can be attached to each report by adding a `metadata`
URL parameter to the reporting endpoint. That value will be copied verbatim
into the logged report.

For example a report sent to `https://collector.example.com/csp?metadata=foobar`
will include field `metadata` with value `foobar`.

If `--query-params-metadata` is set, instead all query parameters are logged
as a map, e.g. `https://collector.example.com/csp?env=production&mode=enforce`
will result in `"metadata": {"env": "production", "mode": "enforce"}` in JSON
format, and `metadata="map[env:production mode:enforce]"` in text format.

### Output formats

The output format can be controlled by passing `--output-format <type>`
to the executable. Available formats are:

- **Text**: [logfmt](https://brandur.org/logfmt) key/value pairs, quoting
  values that are empty or contain spaces, quotes or `=`. Example:
  `blocked_uri=inline document_uri="https://example.com/a b" ...`
- **JSON**: Single line, compressed JSON object. Example:
  `{"blocked_uri":"about:blank"}`

The default formatter is text.

## Metrics

Prometheus metrics are exposed on a dedicated endpoint:

- Address: `127.0.0.1:9090` (default)
- Path: `/metrics`
- Full URL: `http://127.0.0.1:9090/metrics`

The Docker image listens for metrics on `0.0.0.0` instead, since `127.0.0.1`
inside a container can only be reached from the container itself. Publish the
port to scrape it, e.g. `docker run -p 8080:8080 -p 9090:9090
jacobbednarz/go-csp-collector`. That default is the image's only argument,
so if you pass any flags of your own, include `--metrics-bind-addr 0.0.0.0`
with them.

The collector exports:

| Metric | Type | Labels | Description |
| ------ | ---- | ------ | ----------- |
| `csp_collector_reports_total` | Counter | `handler`, `mode` | Successfully processed CSP or Reporting API reports. `mode` is `enforced` or `report_only`, except on `/reporting-api/default`, where it's the report type for known Reporting API types and `reporting-api-default` for anything else |
| `csp_collector_nel_reports_total` | Counter | `mode` | **Deprecated**, use `csp_collector_reports_total{handler="nel"}`, which counts the same reports. It will be removed in a future release |
| `csp_collector_reports_filtered_total` | Counter | `handler`, `reason` | Reports dropped by URI/domain filters |
| `csp_collector_reports_ignored_total` | Counter | `handler`, `reason` | Reports intentionally ignored (for example unsupported NEL types) |
| `csp_collector_reports_errors_total` | Counter | `handler`, `type` | Rejected reports: decode or validation failures, or a request body over the 5 MiB limit (`body_too_large`) |
| `csp_collector_http_request_duration_seconds` | Histogram | `handler`, `route`, `method`, `code` | HTTP request duration for report-ingestion endpoints |
| `csp_collector_http_requests_in_flight` | Gauge | `handler`, `route` | Active in-flight report-ingestion requests |
| `go_*` / `process_*` | Various | client-go defaults | Runtime and process health metrics |

Example Prometheus scrape config:

```yaml
scrape_configs:
  - job_name: "go-csp-collector"
    static_configs:
      - targets: ["127.0.0.1:9090"]
```

If you expose metrics on a non-localhost interface using `--metrics-bind-addr`, protect access with network controls (firewall rules, private network, or service mesh policy).

## Logging and visualisation

Reports are logged to stdout. If you'd rather have them end up in a file,
redirect the output:

```sh
./csp_collector >> /path/to/violations.log
```

This project purposely doesn't try to solve the problem of visualising the
report data, because there are already plenty of good tools for it. Once
reports are being collected, ship them to your favourite log aggregation tool.

## Releasing

- Check out `master`.
- Create a tag and push it.
- GitHub Actions builds and publishes the release, the Docker image and the
  Helm chart.

[1]: https://github.com/jacobbednarz/go-csp-collector/blob/master/sample.filterlist.txt
[2]: https://github.com/jacobbednarz/go-csp-collector/releases
[3]: https://github.com/jacobbednarz/go-csp-collector/tree/master/deployments/kubernetes-helm/README.md
[4]: https://github.com/jacobbednarz/go-csp-collector/tree/master/init
