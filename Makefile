VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/tripnine/flowtrim/internal/app.Version=$(VERSION)

.PHONY: build test bench lint docker demo clean
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...
test:
	go test -race ./...
bench:
	go test -run xxx -bench . -benchmem ./internal/rules/
lint:
	gofmt -l . | (! grep .) && go vet ./...
docker:
	docker build -f deploy/docker/Dockerfile --build-arg VERSION=$(VERSION) -t flowtrim:$(VERSION) .
demo:
	docker compose -f deploy/docker/docker-compose.demo.yaml up --build
clean:
	rm -rf bin
