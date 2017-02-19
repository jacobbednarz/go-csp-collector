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

### Running

```sh
$ go build csp_collector.go
$ ./csp_collector
```

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

[1]: https://github.com/jacobbednarz/go-csp-collector/blob/master/csp_collector.go#L60-L81
