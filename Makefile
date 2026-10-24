.PHONY: test build vet smoke secret-scan

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
	go build -o "$(BIN_DIR)/xandbox-launch" ./cmd/xandbox-launch
	go build -o "$(BIN_DIR)/xandbox-ingress-launch" ./cmd/xandbox-ingress-launch
	CGO_ENABLED=0 go build -o "$(BIN_DIR)/xandbox-ready" ./cmd/xandbox-ready

	go build -o "$(BIN_DIR)/xandbox-keygen" ./cmd/xandbox-keygen
	go build -o "$(BIN_DIR)/xandbox-guestctl" ./cmd/xandbox-guestctl
	go build -o "$(BIN_DIR)/xandbox-template" ./cmd/xandbox-template
	@if [ "$$(go env GOOS)" = linux ]; then CGO_ENABLED=0 go build -o "$(BIN_DIR)/xandbox-agent" ./cmd/xandbox-agent; fi
	@if [ "$$(go env GOOS)" = linux ]; then CGO_ENABLED=0 go build -o "$(BIN_DIR)/xandbox-warden" ./cmd/xandbox-warden; fi
	@if [ "$$(go env GOOS)" = linux ]; then CGO_ENABLED=0 go build -o "$(BIN_DIR)/xandbox-gateway" ./cmd/xandbox-gateway; fi

smoke: build
	python3 scripts/smoke.py --daemon "$(BIN_DIR)/sandboxd" --cli "$(BIN_DIR)/sandboxctl"
	python3 scripts/auth_smoke.py --daemon "$(BIN_DIR)/sandboxd" --cli "$(BIN_DIR)/sandboxctl" --keygen "$(BIN_DIR)/xandbox-keygen" --node "$(BIN_DIR)/xandbox-node"
	python3 scripts/metadata_smoke.py --daemon "$(BIN_DIR)/sandboxd" --node "$(BIN_DIR)/xandbox-node"
	python3 scripts/session_smoke.py --daemon "$(BIN_DIR)/sandboxd"
	python3 scripts/metrics_smoke.py --daemon "$(BIN_DIR)/sandboxd"
	python3 scripts/node_control_smoke.py --daemon "$(BIN_DIR)/sandboxd" --node "$(BIN_DIR)/xandbox-node"
	python3 scripts/diagnostics_smoke.py --daemon "$(BIN_DIR)/sandboxd" --node "$(BIN_DIR)/xandbox-node"

# Install explicitly into a private directory first; never auto-install a tool.
secret-scan:
	@test -n "$(SECRET_SCANNER)" || (echo 'set SECRET_SCANNER to the pinned private executable' >&2; exit 1)
	python3 -m unittest discover -s scripts -p test_secret_scan.py
	python3 scripts/secret_scan_smoke.py --scanner "$(SECRET_SCANNER)"
	python3 scripts/secret_scan.py --scanner "$(SECRET_SCANNER)"
