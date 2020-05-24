This is a content security policy violation collector written in Golang.

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
$ go build csp_collector.go
$ ./csp_collector
```

#### Building for Docker

You will either need to build within a docker container for the purpose, or use  `CGO_ENABLED=0` flag
to make the build compatible with alpine linux in a docker container.

```sh
$ CGO_ENABLED=0 go build csp_collector.go
```

### Command Line Options

| Flag  | Description |
|-------|:------------|
|version|Shows the version string before exiting|
|debug  |Runs in debug mode producing more verbose output|
|port	|Port to run on, default 8080|
|filter-file|Reads the blocked URI filter list from the specified file. Note one filter per line|


See the sample.filterlist.txt file as an example of the filter list in a file

### Request metadata

Additional information can be attached to each report by adding a `metadata`
url parameter to each report. That value will be copied verbatim into the
logged report.

For example a report sent to `https://collector.example.com/?metadata=foobar`
will include field `metadata` with value `foobar`.

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

[1]: https://github.com/jacobbednarz/go-csp-collector/blob/master/sample.filterlist.txt
[2]: https://github.com/jacobbednarz/go-csp-collector/releases
[3]: https://github.com/jacobbednarz/go-csp-collector/tree/master/deployments/kubernetes-helm/README.md
