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
	go build -o "$(BIN_DIR)/xandbox-node" ./cmd/xandbox-node

	go build -o "$(BIN_DIR)/xandbox-keygen" ./cmd/xandbox-keygen
	go build -o "$(BIN_DIR)/xandbox-guestctl" ./cmd/xandbox-guestctl
	go build -o "$(BIN_DIR)/xandbox-template" ./cmd/xandbox-template
	@if [ "$$(go env GOOS)" = linux ]; then CGO_ENABLED=0 go build -o "$(BIN_DIR)/xandbox-agent" ./cmd/xandbox-agent; fi
	@if [ "$$(go env GOOS)" = linux ]; then CGO_ENABLED=0 go build -o "$(BIN_DIR)/xandbox-warden" ./cmd/xandbox-warden; fi
	@if [ "$$(go env GOOS)" = linux ]; then CGO_ENABLED=0 go build -o "$(BIN_DIR)/xandbox-gateway" ./cmd/xandbox-gateway; fi

smoke: build
	python3 scripts/smoke.py --daemon "$(BIN_DIR)/sandboxd" --cli "$(BIN_DIR)/sandboxctl"
	python3 scripts/auth_smoke.py --daemon "$(BIN_DIR)/sandboxd" --cli "$(BIN_DIR)/sandboxctl" --keygen "$(BIN_DIR)/xandbox-keygen"
	python3 scripts/metadata_smoke.py --daemon "$(BIN_DIR)/sandboxd" --node "$(BIN_DIR)/xandbox-node"
	python3 scripts/session_smoke.py --daemon "$(BIN_DIR)/sandboxd"
	python3 scripts/metrics_smoke.py --daemon "$(BIN_DIR)/sandboxd"
	python3 scripts/node_control_smoke.py --daemon "$(BIN_DIR)/sandboxd" --node "$(BIN_DIR)/xandbox-node"
