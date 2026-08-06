# kameas-relay — spec 074 Lane A.
#
# `make check` is the gate: gofmt, go vet, and the full race suite. The race
# suite includes the two halves of the §XII condition-2 proof and neither may
# be skipped:
#
#   * structural  — internal/fakerelay/denylist_test.go walks the import graph
#                   of every relay package and fails the build if one reaches
#                   a crypto primitive or endpoint code.
#   * behavioural — sc2/noplaintext_test.go drives full E2E sessions through
#                   the REAL relay with known-plaintext canaries and asserts
#                   the canary is absent from every store record, log line,
#                   health surface, and error message.
#
# A red SC-2 is a ship-blocking constitutional failure, not a flaky test.

GO      ?= go
PKGS    ?= ./...
DOCKER  ?= docker
IMAGE   ?= kameas-relay
TAG     ?= dev

# Test parallelism. Bounded by default: the race detector plus WebSocket
# suites open a lot of file descriptors, and unbounded -p on a dev laptop
# running several suites at once can exhaust the process file table.
TESTFLAGS ?= -race -p 2 -count=1

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*?## ' $(MAKEFILE_LIST) \
		| awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-16s\033[0m %s\n", $$1, $$2}'

.PHONY: check
check: fmt-check vet test ## fmt + vet + race tests (the gate)

.PHONY: fmt-check
fmt-check: ## Fail if any file is not gofmt-clean
	@out="$$(gofmt -l . )"; \
	if [ -n "$$out" ]; then \
		echo "gofmt: the following files are not formatted:"; \
		echo "$$out"; \
		exit 1; \
	fi

.PHONY: fmt
fmt: ## Rewrite files with gofmt
	gofmt -w .

.PHONY: vet
vet: ## go vet
	$(GO) vet $(PKGS)

.PHONY: test
test: ## Race tests (includes the deny-list and SC-2 gates)
	$(GO) test $(TESTFLAGS) $(PKGS)

.PHONY: build
build: ## Build every binary into bin/
	@mkdir -p bin
	$(GO) build -trimpath -o bin/ $(PKGS)

.PHONY: run-fake
run-fake: ## Run the in-memory fake relay on 127.0.0.1:7900
	$(GO) run ./cmd/fakerelay -addr 127.0.0.1:7900

.PHONY: run
run: ## Run the real relay (relayd) from the environment
	$(GO) run ./cmd/relayd

.PHONY: demo
demo: ## One-command end-to-end exit gate (in-process fake relay + host)
	$(GO) run ./cmd/remotectl demo

.PHONY: docker
docker: ## Build the relayd container image
	$(DOCKER) build -t $(IMAGE):$(TAG) .

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy
