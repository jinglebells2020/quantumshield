BINARY=qs
SERVER_BINARY=qsserver
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")
LDFLAGS=-ldflags "-X quantumshield/pkg/version.Version=$(VERSION) -s -w"

.PHONY: build test scan clean docker

build:
	go build $(LDFLAGS) -o bin/$(BINARY) ./cmd/qs
	go build $(LDFLAGS) -o bin/$(SERVER_BINARY) ./cmd/qsserver

test:
	go test ./... -v -race

scan: build
	./bin/$(BINARY) scan . --format table

clean:
	rm -rf bin/

docker:
	docker build -t quantumshield:$(VERSION) .
