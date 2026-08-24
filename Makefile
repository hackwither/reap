.PHONY: build vet fmt test check run-list

build:
	go build -o bin/reap ./cmd/reap

fmt:
	gofmt -w .

vet:
	go vet ./...

test:
	go test ./... -v

check: fmt vet build test

run-list: build
	./bin/reap --list-probes

docker-build:
	docker build -t reap:dev .

snapshot:
	goreleaser build --snapshot --clean
