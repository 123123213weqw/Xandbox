.PHONY: test build vet smoke

BIN_DIR ?= bin

test:
	go test -race ./...

vet:
	go vet ./...

build:
	mkdir -p "$(BIN_DIR)"
	go build -o "$(BIN_DIR)/sandboxd" ./cmd/sandboxd
	go build -o "$(BIN_DIR)/sandboxctl" ./cmd/sandboxctl

smoke: build
	python3 scripts/smoke.py --daemon "$(BIN_DIR)/sandboxd" --cli "$(BIN_DIR)/sandboxctl"
