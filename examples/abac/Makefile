DIST_DIR := _dist
GO_CODE_DIR := pkg internal
TEST_OUTPUT_DIR := ${DIST_DIR}/tests
BUILD_DIR := ${DIST_DIR}/build

# Database migrations
MIGRATIONS_DIR := database/migrations

# Database seed
SEEDS_DIR := database/seeds
SEED_MIGRATIONS_TABLE := seed_version

DEFAULT_VERSION := v0.0.0

.PHONY: migrate-db
migrate-db:
	@migrate -source file://$(MIGRATIONS_DIR) \
		-database postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST)/$(POSTGRES_DB_DEMO)?sslmode=$(POSTGRES_SSL_MODE) \
		up
	@migrate -source file://$(MIGRATIONS_DIR) \
		-database postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST)/$(POSTGRES_DB_TEST)?sslmode=$(POSTGRES_SSL_MODE) \
		up

.PHONY: seed-db
seed-db:
	@migrate -source file://$(SEEDS_DIR) \
		-database "postgres://$(POSTGRES_USER):$(POSTGRES_PASSWORD)@$(POSTGRES_HOST)/$(POSTGRES_DB_DEMO)?sslmode=$(POSTGRES_SSL_MODE)&x-migrations-table=$(SEED_MIGRATIONS_TABLE)" \
		up

# App
.PHONY: test
test: migrate-db lint-go test-go

.PHONY: build
build: cleanup-build
	@CURRENT_VERSION=$(shell git describe --tags --abbrev=0 2>/dev/null || echo $(DEFAULT_VERSION)); \
	echo "Building api (version $$CURRENT_VERSION)..."; \
	go build -o $(BUILD_DIR)/api \
		-a -ldflags "-X 'github.com/CameronXie/access-control-explorer/examples/abac/internal/version.Version=$$CURRENT_VERSION' -extldflags '-s -w -static'" \
		./cmd/api; \
	cp -r ./cmd/api/policies $(BUILD_DIR)/policies

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

.PHONY: cleanup-build
cleanup-build:
	@rm -rf ${BUILD_DIR}
	@mkdir -p ${BUILD_DIR}
