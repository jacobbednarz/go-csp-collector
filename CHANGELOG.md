## v0.0.13 (Unreleased)

## v0.0.12 

- Shuffle internals around to add dedicated CSP endpoints and make way for NEL and reporting API.

## v0.0.11

**Improvements**

- Add `log-client-ip` flag for logging client IP with requests
- Add `log-truncated-client-ip` flag to use in conjunction with `log-client-ip` for logging only the IP range
- Add `truncated-query-fragment` flag to remove all query strings and fragments (if set) from all URLs transmitted by the client
- Add `query-params-metadata` flaf to log all query parameters of the report URL as a map in the `metadata` field
- Bump to Go 1.19

## v0.0.10

**Improvements**

- Fix README links for kubernetes-helm documentation

## v0.0.9 - Definitely Maybe

**Features**

- Add support for Kubernetes Helm deployments ([#17](https://github.com/jacobbednarz/go-csp-collector/issues/17))

**Improvements**

- Filter MS application schemes ([#43](https://github.com/jacobbednarz/go-csp-collector/issues/43))

## v0.0.8

**Improvements**

- Updated format of `-version` output to be `MAJOR.MINOR.PATCH+GIT_SHA` ([#42](https://github.com/jacobbednarz/go-csp-collector/issues/42))

## v0.0.7

**Improvements**

- Allow metadata smuggling by appending `metadata` query parameter to reports ([#40](https://github.com/jacobbednarz/go-csp-collector/issues/40))

## v0.0.6

**Improvements**

- Ignore document-uri values that don't start with `http` ([#39](https://github.com/jacobbednarz/go-csp-collector/issues/39))

## v0.0.5

**Improvements**

- Adds ability to have comments in filter list file ([#37](https://github.com/jacobbednarz/go-csp-collector/issues/37))

## v0.0.4

**Improvements**

- Dependency upgrades
- Update Go version and use modules

**Features**

- Add support for JSON output
- Docker support
- More invalid URLs

## v0.0.3

**Improvements**

- Update README links and releases mention
- Adds coverage for ensuring all required keys are outputted
- Add coverage for ValidateViolation function
- Use lowercase in error messages because the cool kids do
- Don't track the dist directory
- 👋 1.6 and hello 1.8
- Add coverage for healthcheck endpoint
- Don't include hostname in urlStr param
- Add test coverage for disallowed methods
- Add test coverage for disallowed methods on root

**Fixes**

- Don't panic for invalid payloads
- Ensure we always have a timestamp

## v0.0.2

**Features**

- Add `-debug` flag
- add darwin builds

**Improvements**

- add goreleaser for packaging
