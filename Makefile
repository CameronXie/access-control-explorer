DIST_DIR := _dist
GO_CODE_DIR := abac
TEST_OUTPUT_DIR := ${DIST_DIR}/tests

EXAMPLES_DIR ?= examples
EXAMPLE_DIRS := $(shell find $(EXAMPLES_DIR) -mindepth 1 -maxdepth 1 -type d -print)

# Docker
.PHONY: up
up: create-dev-env
	@docker compose up --build -d

.PHONY: down
down:
	@docker compose down -v

.PHONY: create-dev-env
create-dev-env:
	@if [ ! -f .env ]; then \
		echo ".env file not found, creating from .env.example..."; \
		PRIVATE_KEY_B64=$$(openssl genpkey -algorithm RSA 2>/dev/null | base64 -w 0); \
		PUBLIC_KEY_B64=$$(echo $$PRIVATE_KEY_B64 | base64 -d | openssl rsa -pubout 2>/dev/null | base64 -w 0); \
		sed -e "s|PRIVATE_KEY_BASE64=.*|PRIVATE_KEY_BASE64=$$PRIVATE_KEY_B64|" \
			-e "s|PUBLIC_KEY_BASE64=.*|PUBLIC_KEY_BASE64=$$PUBLIC_KEY_B64|" .env.example > .env; \
	else \
		echo ".env file found, proceeding..."; \
	fi

# CI/CD
.PHONY: ci-%
ci-%: create-dev-env
	# Setting GOFLAGS=-buildvcs=false due to an issue with running golangci-lint in Docker container in GitHub Actions.
	# Need to revisit this flag once the underlying issue with VCS stamping is resolved.
	@docker compose run --rm dev sh -c 'GOFLAGS=-buildvcs=false make $*'

# Dev
.PHONY: test
test: lint-actions lint-go test-go

.PHONY: test-examples
test-examples:
	@for d in $(EXAMPLE_DIRS); do $(MAKE) -C "$$d" test; done

## App
.PHONY: lint-go
lint-go:
	@echo "Running Go linter on code in $(GO_CODE_DIR)..."
	@golangci-lint fmt $(addsuffix /..., $(GO_CODE_DIR)) -v
	@golangci-lint run $(addsuffix /..., $(GO_CODE_DIR)) -v

.PHONY: test-go
test-go:
	@rm -rf ${TEST_OUTPUT_DIR}
	@mkdir -p ${TEST_OUTPUT_DIR}
	@go clean -testcache
	@echo "Running Go tests..."
	@go test \
		-cover \
		-coverprofile=cp.out \
		-outputdir=${TEST_OUTPUT_DIR} \
		-race \
		-v \
		-failfast \
		$(addprefix `pwd`/, $(addsuffix /..., $(GO_CODE_DIR)))
	@go tool cover -html=${TEST_OUTPUT_DIR}/cp.out -o ${TEST_OUTPUT_DIR}/cp.html

## Action
.PHONY: lint-actions
lint-actions:
	@actionlint
