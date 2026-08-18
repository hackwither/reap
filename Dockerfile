# Build a static binary, then ship it on a minimal base. reap has no
# third-party Go dependencies, so there is nothing to vendor or audit here.
FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /out/reap ./cmd/reap

FROM alpine:3.20
# Certificates are required: reap scans https:// endpoints and inspects their
# certificates, so a scratch image would fail every TLS target.
RUN apk add --no-cache ca-certificates \
    && adduser -D -u 10001 reap
WORKDIR /reap
COPY --from=build /out/reap /usr/local/bin/reap
# Templates and fingerprints are loaded from disk at runtime; without them the
# container silently runs with no templates and no discovery detectors.
COPY templates ./templates
COPY fingerprints ./fingerprints
USER reap
ENTRYPOINT ["reap"]
CMD ["--help"]
