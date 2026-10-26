FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG REVISION=dev
RUN CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.Rev=${REVISION}" -o /csp_collector .

FROM alpine:3.24.2
LABEL maintainer="https://github.com/jacobbednarz/go-csp-collector"
COPY --from=build /csp_collector /
EXPOSE 8080 9090

RUN addgroup -Sg 1000 csp_collector && \
    adduser -SG csp_collector -u 1000 -h /home/csp_collector csp_collector

# A numeric user lets Kubernetes verify runAsNonRoot without a runAsUser.
USER 1000:1000

ENTRYPOINT ["/csp_collector"]

# Inside a container 127.0.0.1 is only reachable from the container itself,
# so metrics listen on every interface. They're still only exposed when the
# port is published. Passing any arguments to `docker run` replaces this.
CMD ["--metrics-bind-addr", "0.0.0.0"]
