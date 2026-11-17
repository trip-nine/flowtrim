VERSION ?= $(shell cat VERSION)
LDFLAGS := -s -w -X github.com/trip-nine/flowtrim/internal/app.Version=$(VERSION)
PLATFORMS := linux/amd64 linux/arm64 darwin/arm64 darwin/amd64 windows/amd64

.PHONY: build test bench lint demo docker docker-demo samples release clean
build:
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o bin/ ./cmd/...
test:
	go test -race ./...
bench:
	go test -run xxx -bench . -benchmem ./internal/rules/ ./internal/enrich/
lint:
	test -z "$$(gofmt -l .)" && go vet ./...
demo: build
	./demo/run-demo.sh
docker:
	docker build -f deploy/docker/Dockerfile --build-arg VERSION=$(VERSION) -t flowtrim:$(VERSION) .
docker-demo:
	docker compose -f deploy/docker/docker-compose.demo.yaml up --build
samples:
	go run ./tools/mkdemodb demo/samples
	go run ./cmd/flowgen gen -format ipfix -rate 1300 -duration 60s -fast -send=false -seed 7 -pcap demo/samples/enterprise-mix.ipfix.pcap -manifest demo/samples/enterprise-mix.ipfix.json
	go run ./cmd/flowgen gen -format v9 -rate 800 -duration 30s -fast -send=false -seed 11 -pcap demo/samples/campus.v9.pcap -manifest demo/samples/campus.v9.json
	go run ./cmd/flowgen gen -format v5 -rate 500 -duration 30s -fast -send=false -seed 13 -dup-fraction 0.2 -pcap demo/samples/branch.v5.pcap -manifest demo/samples/branch.v5.json
release:
	rm -rf dist && mkdir -p dist
	@for p in $(PLATFORMS); do os=$${p%/*}; arch=$${p#*/}; ext=; [ $$os = windows ] && ext=.exe; \
	  d=dist/flowtrim_$(VERSION)_$${os}_$${arch}; mkdir -p $$d; \
	  for c in flowtrim flowgen mockhec; do CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch go build -trimpath -ldflags "$(LDFLAGS)" -o $$d/$$c$$ext ./cmd/$$c || exit 1; done; \
	  cp LICENSE NOTICE README.md CHANGELOG.md $$d/; mkdir -p $$d/examples $$d/demo; cp -r examples/* $$d/examples/; cp -r demo/* $$d/demo/; \
	  (cd dist && tar czf $$(basename $$d).tar.gz $$(basename $$d)); rm -rf $$d; done
	cd dist && sha256sum *.tar.gz > SHA256SUMS
clean:
	rm -rf bin dist
