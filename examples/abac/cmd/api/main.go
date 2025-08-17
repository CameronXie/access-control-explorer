package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/CameronXie/access-control-explorer/abac/decisionmaker"
	"github.com/CameronXie/access-control-explorer/abac/decisionmaker/policyevaluator/opa"
	ip "github.com/CameronXie/access-control-explorer/abac/infoprovider"
	"github.com/CameronXie/access-control-explorer/abac/policyprovider/filestore"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/advice"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/api/rest/handler"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/api/rest/middleware"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/enforcer"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/enforcer/jwt"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/enforcer/operations"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/infoprovider"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/obligation"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/policyresolver"
	repository "github.com/CameronXie/access-control-explorer/examples/abac/internal/repository/postgres"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/requestorchestrator"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/requestorchestrator/infoanalyser"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/version"
	"github.com/CameronXie/access-control-explorer/examples/abac/pkg/keyfetcher"
	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	DefaultPort = "8080"

	PolicyDir        = "policies"
	RegoQuery        = "data.abac.result"
	DefaultPolicyKey = "default.rego"
	RBACPolicyKey    = "rbac.rego"
	PolicyVersion    = "v1"

	TokenTTL                    = 1 * time.Hour
	DecisionCacheHintHeaderName = "X-ABAC-Decision-TTL"

	JWTClockSkewTolerance = 5 * time.Minute
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	logger.Info("api_starting", "version", version.Version)

	// Database connection
	dbPool, err := initializeDatabase(logger, fmt.Sprintf(
		"postgres://%s:%s@%s/%s?sslmode=%s",
		os.Getenv("POSTGRES_USER"),
		os.Getenv("POSTGRES_PASSWORD"),
		os.Getenv("POSTGRES_HOST"),
		os.Getenv("POSTGRES_DB_DEMO"),
		os.Getenv("POSTGRES_SSL"),
	))
	if err != nil {
		logger.Error("db_init_failed", "error", err)
		os.Exit(1)
	}
	defer dbPool.Close()

	// Policy location
	policyPath, err := resolvePolicyPath(PolicyDir, "POLICY_DIR")
	if err != nil {
		logger.Error("policy_path_resolve_failed", "error", err)
		os.Exit(1)
	}

	// Repositories
	userRepo := repository.NewUserRepository(dbPool)
	orderRepo := repository.NewOrderRepository(dbPool)
	rbacRepo := repository.NewRBACRepository(dbPool)

	// Auth config
	issuer := os.Getenv("JWT_ISSUER")
	audience := os.Getenv("JWT_AUDIENCE")

	// Create JWT middleware
	jwtMiddleware := middleware.NewJWTAuthMiddleware(middleware.JWTConfig{
		KeyFetcher: keyfetcher.FromBase64Env("PUBLIC_KEY_BASE64"),
		Issuer:     issuer,
		Audience:   audience,
		ClockSkew:  JWTClockSkewTolerance,
	})

	// Enforcer (PEP)
	enforcerMiddleware, err := initEnforcer(policyPath, userRepo, orderRepo, rbacRepo, logger)
	if err != nil {
		logger.Error("enforcer_init_failed", "error", err)
		os.Exit(1)
	}

	// REST handlers
	orderHandler := handler.NewOrderHandler(orderRepo, logger)
	authHandler := handler.NewAuthHandler(
		userRepo,
		&handler.AuthConfig{
			KeyFetcher: keyfetcher.FromBase64Env("PRIVATE_KEY_BASE64"),
			Issuer:     issuer,
			Audience:   audience,
			TokenTTL:   TokenTTL,
		},
		logger,
	)

	// Routing
	mux := buildServeMux(authHandler, orderHandler, jwtMiddleware, enforcerMiddleware)

	// HTTP server with sensible timeouts
	port := os.Getenv("PORT")
	if port == "" {
		port = DefaultPort
	}
	server := &http.Server{
		Addr:              fmt.Sprintf(":%s", port),
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("api_listening", "addr", server.Addr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("api_serve_failed", "error", err)
		os.Exit(1)
	}
}

// initializeDatabase creates a pool and verifies connectivity.
func initializeDatabase(logger *slog.Logger, connectionString string) (*pgxpool.Pool, error) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, connectionString)
	if err != nil {
		return nil, fmt.Errorf("create_pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping_db: %w", err)
	}

	return pool, nil
}

// initEnforcer wires PRP, PDP, Context Handler, and PEP middleware.
func initEnforcer(
	policyPath string,
	userRepo infoprovider.UserAttributesRepository,
	orderRepo infoprovider.OrderAttributesRepository,
	rbacRepo infoprovider.RBACRepository,
	logger *slog.Logger,
) (*enforcer.Enforcer, error) {
	// PRP: policy provider
	policyProvider := filestore.New(policyPath)

	// PDP: decision maker
	decisionMaker := decisionmaker.NewDecisionMaker(
		policyProvider,
		opa.NewEvaluator(RegoQuery),
		decisionmaker.WithPolicyResolver(policyresolver.NewDefaultResolver(DefaultPolicyKey, PolicyVersion)),
		decisionmaker.WithPolicyResolver(policyresolver.NewRBACResolver(RBACPolicyKey, PolicyVersion)),
	)

	// Context Handler: enrich request and call PDP
	orchestrator := requestorchestrator.NewRequestOrchestrator(
		[]requestorchestrator.InfoAnalyser{
			infoanalyser.NewRBACAnalyser(infoprovider.InfoTypeRBAC),
		},
		infoprovider.NewInfoProvider(map[infoprovider.InfoType]ip.InfoProvider{
			infoprovider.InfoTypeUser:  infoprovider.NewUserProvider(userRepo),
			infoprovider.InfoTypeOrder: infoprovider.NewOrderProvider(orderRepo),
			infoprovider.InfoTypeRBAC:  infoprovider.NewRoleBasedAccessProvider(rbacRepo),
		}),
		decisionMaker,
	)

	// HTTP request extractors for operations
	orderCreateExtractor, err := operations.NewOrderExtractor(operations.ActionCreate)
	if err != nil {
		return nil, fmt.Errorf("new_order_create_extractor: %w", err)
	}

	orderReadExtractor, err := operations.NewOrderExtractor(
		operations.ActionRead,
		operations.WithIDExtractor(operations.ExtractOrderIDFromPath),
	)
	if err != nil {
		return nil, fmt.Errorf("new_order_read_extractor: %w", err)
	}

	// PEP request extractor
	requestExtractor, err := enforcer.NewRequestExtractor(
		enforcer.WithSubjectExtractor(jwt.NewSubjectExtractor()),
		enforcer.WithOperationExtractor("/orders", http.MethodPost, orderCreateExtractor),
		enforcer.WithOperationExtractor("/orders/*", http.MethodGet, orderReadExtractor),
	)
	if err != nil {
		return nil, fmt.Errorf("new_request_extractor: %w", err)
	}

	// PEP middleware
	return enforcer.NewEnforcer(
		orchestrator,
		requestExtractor,
		logger,
		enforcer.WithAdviceHandler("cache_hint", advice.NewCacheHintAdviceHandler(DecisionCacheHintHeaderName)),
		enforcer.WithObligationHandler("audit_logging", obligation.NewAuditLogHandler(logger)),
	), nil
}

// buildServeMux wires routes and applies the PEP to API endpoints.
func buildServeMux(
	authHandler *handler.AuthHandler,
	orderHandler *handler.OrderHandler,
	jwtMiddleware *middleware.JWTAuthMiddleware,
	enforcer *enforcer.Enforcer,
) *http.ServeMux {
	root := http.NewServeMux()
	root.Handle("GET /health", http.HandlerFunc(handleHealthCheck))

	api := http.NewServeMux()
	root.Handle("/api/v1/", http.StripPrefix("/api/v1", jwtMiddleware.Handler(enforcer.Enforce(api))))

	root.Handle("POST /auth/signin", http.HandlerFunc(authHandler.SignIn))
	api.Handle("POST /orders", http.HandlerFunc(orderHandler.CreateOrder))
	api.Handle("GET /orders/{id}", http.HandlerFunc(orderHandler.GetOrderByID))
	return root
}

// handleHealthCheck returns a basic health status.
func handleHealthCheck(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`{"status":"healthy"}`))
}

// resolvePolicyPath prefers env var; falls back to executable dir.
func resolvePolicyPath(policyDir string, policyDirEnv string) (string, error) {
	if policyPath := os.Getenv(policyDirEnv); policyPath != "" {
		return policyPath, nil
	}

	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exeDir := filepath.Dir(exe)
	return filepath.Join(exeDir, policyDir), nil
}
