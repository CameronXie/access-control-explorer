DIST_DIR := _dist
GO_CODE_DIR := cmd internal
TEST_OUTPUT_DIR := ${DIST_DIR}/tests
BUILD_DIR := ${DIST_DIR}/build

DEFAULT_VERSION := v0.0.0

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

.PHONY: build
build: cleanup-build test
	@echo "Running api-casbin and api-opa in parallel..."
	@$(MAKE) -j 2 api-casbin api-opa

## App
.PHONY: lint-go
lint-go:
	@echo "Running Go linter on code in $(GO_CODE_DIR)..."
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

.PHONY: api-%
api-%:
	@CURRENT_VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null || echo $(DEFAULT_VERSION)); \
	echo "Building api (version $$CURRENT_VERSION) using $*..."; \
	go build -o ${BUILD_DIR}/api-$* \
		-a -ldflags "-X 'github.com/CameronXie/access-control-explorer/internal/version.Version=$$CURRENT_VERSION' -extldflags '-s -w -static'" \
		-tags $* \
		./cmd

.PHONY: cleanup-build
cleanup-build:
	@rm -rf ${BUILD_DIR}
	@mkdir -p ${BUILD_DIR}

## Action
.PHONY: lint-actions
lint-actions:
	@actionlint
