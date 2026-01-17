.PHONY: build clean install test deps

BINARY=sectimeline
VERSION=1.0.0
BUILD_DIR=build

all: deps build

deps:
	go mod tidy

build:
	@mkdir -p $(BUILD_DIR)
	CGO_ENABLED=0 go build -ldflags="-s -w -X main.Version=$(VERSION)" -o $(BUILD_DIR)/$(BINARY) .

build-all: deps
	@mkdir -p $(BUILD_DIR)
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY)-darwin-arm64 .
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o $(BUILD_DIR)/$(BINARY)-darwin-amd64 .

install: build
	@mkdir -p ~/.config/sectimeline/data
	cp $(BUILD_DIR)/$(BINARY) /usr/local/bin/$(BINARY)
	@echo "Installed $(BINARY) to /usr/local/bin/"

uninstall:
	rm -f /usr/local/bin/$(BINARY)
	@echo "Uninstalled $(BINARY)"

clean:
	rm -rf $(BUILD_DIR)
	go clean

test:
	go test -v ./...

run: build
	./$(BUILD_DIR)/$(BINARY) daemon start -f

.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build      - Build the binary"
	@echo "  build-all  - Build for all platforms"
	@echo "  install    - Install to /usr/local/bin"
	@echo "  uninstall  - Remove from /usr/local/bin"
	@echo "  clean      - Clean build artifacts"
	@echo "  test       - Run tests"
	@echo "  run        - Build and run in foreground"
	@echo "  deps       - Download dependencies"
