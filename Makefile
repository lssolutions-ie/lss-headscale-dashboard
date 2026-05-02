.PHONY: build run lint test tidy clean fmt

BINARY := bin/lss-headscale-dashboard

build:
	go build -o $(BINARY) ./cmd/dashboard

run:
	go run ./cmd/dashboard --config config.example.yaml

lint:
	go vet ./...

test:
	go test ./...

tidy:
	go mod tidy

fmt:
	gofmt -s -w .

clean:
	rm -rf bin dist
