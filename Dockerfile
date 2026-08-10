# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath \
      -ldflags "-s -w -X github.com/hackwither/reap/internal/cli.Version=${VERSION}" \
      -o /out/reap ./cmd/reap

FROM alpine:3.20
RUN apk add --no-cache ca-certificates && \
    adduser -D -u 10001 reap
COPY --from=build /out/reap /usr/local/bin/reap
COPY templates/ /app/templates/
COPY fingerprints/ /app/fingerprints/
WORKDIR /app
USER reap
ENTRYPOINT ["reap"]
CMD ["--help"]
