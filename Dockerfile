FROM golang:1.18-alpine AS build
COPY . /go/src/jacobbednarz/go-csp-collector
WORKDIR /go/src/jacobbednarz/go-csp-collector
RUN set -ex \
  && apk add --no-cache git \
  && go get -d ./... \
  && go build csp_collector.go

FROM alpine:3.16
LABEL maintainer="https://github.com/jacobbednarz/go-csp-collector"
COPY --from=build /go/src/jacobbednarz/go-csp-collector/csp_collector /
EXPOSE 8080

RUN mkdir -p /home/csp_collector && \
    addgroup -Sg 1000 csp_collector &&  \
    adduser  -SG csp_collector -u 1000 -h /home/csp_collector csp_collector && \
    chown csp_collector:csp_collector /home/csp_collector

USER csp_collector

RUN id csp_collector

CMD ["/csp_collector"]
