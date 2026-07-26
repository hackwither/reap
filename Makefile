.PHONY: build vet fmt test check run-list

build:
	go build -o bin/agentrecon ./cmd/agentrecon

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./... -v

check: fmt vet build test

run-list: build
	./bin/agentrecon --list-probes
