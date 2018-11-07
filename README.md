This is a content security policy violation collector written in Golang.

It has been designed to listen on port 8080 and accept POST payloads
containing the violation report. It captures the report and will write
it to STDOUT via Go's logger.

A neat little feature of this tool is that it automatically ignores
unactionable reports. Check out the [full list][1] if you're interested.

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

[1]: https://github.com/jacobbednarz/go-csp-collector/blob/36dacd76a257a9863d4ffb2482b1034558752587/csp_collector.go#L86-L106
[2]: https://github.com/jacobbednarz/go-csp-collector/releases
