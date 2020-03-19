FROM golang:1.14-alpine AS build
COPY . /go/src/jacobbednarz/go-csp-collector
WORKDIR /go/src/jacobbednarz/go-csp-collector
RUN set -ex \
  && apk add --no-cache git \
  && go get -d ./... \
  && go build csp_collector.go

FROM alpine:3.11
LABEL maintainer="https://github.com/jacobbednarz/go-csp-collector"
COPY --from=build /go/src/jacobbednarz/go-csp-collector/csp_collector /
EXPOSE 8080
CMD ["/csp_collector"]
