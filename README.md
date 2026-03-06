This is a content security policy (CSP) violation and network error logging
(NEL) collector written in Golang.

It has been designed to listen on port 8080 and accept POST payloads
containing the violation report. It captures the report and will write
it to STDOUT via Go's logger.

A neat little feature of this tool is that it automatically ignores
unactionable reports. Check out the [default list][1] if you're interested.

### Installation

```sh
$ go get github.com/jacobbednarz/go-csp-collector
```

Alternatively, you can download the binaries from the [release page][2].

### Running

```sh
$ go build -o csp_collector main.go
$ ./csp_collector
```

### Endpoints

#### CSP

- `POST /`: accepts a CSP violation report (recommended to use `/csp` for future proofing though).
- `POST /csp`: accepts a CSP violation report.
- `POST /csp/report-only`: same as `/csp` but appends a `report_only=true` attribute to the log line. Helpful if you have enforced and report-only violations and wish to separate them.
- `OPTIONS /reporting-api/csp`: CORS preflight handler for the Reporting API.
- `POST /reporting-api/csp`: Implementation of the browser Reporting API ([w3c](https://www.w3.org/TR/reporting-1/) / [MDN](https://developer.mozilla.org/en-US/docs/Web/API/Reporting_API)) for CSP violations.

#### NEL (Network Error Logging)

- `POST /nel`: accepts NEL reports for an enforced NEL policy.
- `POST /nel/report-only`: same as `/nel` but appends a `report_only=true` attribute to the log line. Useful when testing a NEL policy before enforcing it.

NEL reports are delivered by the browser via the [Reporting API](https://www.w3.org/TR/reporting-1/) as a JSON array. Each entry with `"type": "network-error"` is logged; other types in a mixed batch are silently skipped.

To enable NEL reporting, send the `NEL` and `Report-To` (or `Reporting-Endpoints`) headers from your server:

```http
Reporting-Endpoints: nel-endpoint="https://collector.example.com/nel"
NEL: {"report_to": "nel-endpoint", "max_age": 31536000}
```

Each logged NEL report includes the following fields:

| Field               | Description                                              |
| ------------------- | -------------------------------------------------------- |
| `report_only`       | `true` when received on the `/nel/report-only` endpoint  |
| `url`               | The URL of the request that failed                       |
| `referrer`          | The referrer at the time of the request                  |
| `type`              | Error type (e.g. `tcp.refused`, `dns.unreachable`, `ok`) |
| `phase`             | Phase of the request: `dns`, `connection`, `application`, or `abandoned` |
| `protocol`          | Network protocol (e.g. `h2`, `http/1.1`)                |
| `method`            | HTTP method (e.g. `GET`, `POST`)                         |
| `status_code`       | HTTP status code (0 if the connection never completed)   |
| `elapsed_time`      | Duration of the request in milliseconds                  |
| `server_ip`         | IP address of the server that handled the request        |
| `sampling_fraction` | Fraction of matching requests that were reported         |
| `metadata`          | Value of the `metadata` query parameter (if present)     |
| `path`              | Path of the collector endpoint that received the report  |

#### Building for Docker

You will either need to build within a docker container for the purpose, or use `CGO_ENABLED=0` flag
to make the build compatible with alpine linux in a docker container.

```sh
$ CGO_ENABLED=0 go build -o csp_collector main.go
```

### Command Line Options

| Flag                    | Description                                                                                                                                                                                       |
| ----------------------- | :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| version                 | Shows the version string before exiting                                                                                                                                                           |
| debug                   | Runs in debug mode producing more verbose output                                                                                                                                                  |
| port                    | Port to run on, default 8080                                                                                                                                                                      |
| filter-file             | Reads the blocked URI filter list from the specified file. Note one filter per line                                                                                                               |
| health-check-path       | Sets path for health checkers to use, default \/\_healthcheck                                                                                                                                     |
| log-client-ip           | Include a field in the log with the IP delivering the report, or the value of the `X-Forwarded-For` header, if present.                                                                           |
| log-truncated-client-ip | Include a field in the log with the truncated IP (to /24 for IPv4, /64 for IPv6) delivering the report, or the value of the `X-Forwarded-For` header, if present. Conflicts with `log-client-ip`. |
| truncate-query-fragment | Remove all query strings and fragments (if set) from all URLs transmitted by the client                                                                                                           |
| query-params-metadata   | Log all query parameters of the report URL as a map in the `metadata` field                                                                                                                       |

See the `sample.filterlist.txt` file as an example of the filter list in a file

### Request metadata

Additional information can be attached to each report by adding a `metadata`
url parameter to each report. That value will be copied verbatim into the
logged report.

For example a report sent to `https://collector.example.com/?metadata=foobar`
will include field `metadata` with value `foobar`.

If `query-params-metadata` is set, instead all query parameters are logged as a
map, e.g. `https://collector.example.com/?env=production&mode=enforce` will
result in `"metadata": {"env": "production", "mode": "enforce"}` in JSON
format, and `metadata="map[env:production mode:enforce]"` in default format.

### `report-only` mode

Both CSP and NEL have dedicated `report-only` endpoints (`/csp/report-only` and
`/nel/report-only`). Reports received on these endpoints are logged identically
to their enforced counterparts, but with `report_only=true` in the log output.
This lets you distinguish enforced violations from report-only ones in your log
aggregation tool without needing separate collector instances.

### Output formats

The output format can be controlled by passing `--output-format <type>`
to the executable. Available formats are:

- **Text**: A key/value output that quotes all the values. Example:
  `blocked_uri="about:blank" ...`
- **JSON**: Single line, compressed JSON object. Example:
  `{"blocked_uri":"about:blank"}`

The default formatter is text.

### Writing to a file instead of just STDOUT

If you'd rather have these violations end up in a file, I suggest just
redirecting the output into a file like so:

```sh
$ ./csp_collector 2>> /path/to/violations.log
```

### Visualisation

This project purposely doesn't try to solve the problem of visualing the
violation data because there are already a bunch of great solutions out
there. Once you have your violations being collected, be sure to slurp
them into your favourite log aggregation tool.

### Deployments

Currently supported deployment mechanisms:

- [kubernetes/helm][3]
- [systemd][4]

[1]: https://github.com/jacobbednarz/go-csp-collector/blob/master/sample.filterlist.txt
[2]: https://github.com/jacobbednarz/go-csp-collector/releases
[3]: https://github.com/jacobbednarz/go-csp-collector/tree/master/deployments/kubernetes-helm/README.md
[4]: https://github.com/jacobbednarz/go-csp-collector/tree/master/init
