package enforcer

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
)

// AdviceHandler defines the interface for handling advice
type AdviceHandler interface {
	Handle(ctx context.Context, advice ro.Advice, w http.ResponseWriter, r *http.Request) error
}

// ObligationHandler defines the interface for handling obligations
type ObligationHandler interface {
	Handle(ctx context.Context, obligation ro.Obligation, w http.ResponseWriter, r *http.Request) error
}

// RequestExtractor defines the interface for extracting access request from HTTP request
type RequestExtractor interface {
	Extract(ctx context.Context, r *http.Request) (*ro.AccessRequest, error)
}

// ErrorResponse represents a standardized error response
type ErrorResponse struct {
	Error   string `json:"error"`
	Message string `json:"message"`
}

// Enforcer represents the Policy Enforcement Point middleware
// Note: PEP logging here is operational (observability and correlation).
// It is intentionally distinct from any auditing performed via obligations.
type Enforcer struct {
	orchestrator       ro.RequestOrchestrator
	requestExtractor   RequestExtractor
	adviceHandlers     map[string]AdviceHandler
	obligationHandlers map[string]ObligationHandler
	errorHandler       func(w http.ResponseWriter, r *http.Request, statusCode int, errorResp ErrorResponse)
	logger             *slog.Logger
}

// Option defines configuration options for Enforcer
type Option func(*Enforcer)

// NewEnforcer creates a new Enforcer instance with the given request orchestrator and options
func NewEnforcer(orchestrator ro.RequestOrchestrator, extractor RequestExtractor, logger *slog.Logger, options ...Option) *Enforcer {
	enforcer := &Enforcer{
		orchestrator:       orchestrator,
		requestExtractor:   extractor,
		adviceHandlers:     make(map[string]AdviceHandler),
		obligationHandlers: make(map[string]ObligationHandler),
		errorHandler:       defaultErrorHandler,
		logger:             logger,
	}

	for _, option := range options {
		option(enforcer)
	}

	return enforcer
}

// WithAdviceHandler registers an advice handler for a specific advice ID
func WithAdviceHandler(adviceID string, handler AdviceHandler) Option {
	return func(e *Enforcer) {
		e.adviceHandlers[adviceID] = handler
	}
}

// WithObligationHandler registers an obligation handler for a specific obligation ID
func WithObligationHandler(obligationID string, handler ObligationHandler) Option {
	return func(e *Enforcer) {
		e.obligationHandlers[obligationID] = handler
	}
}

// WithErrorHandler sets a custom error response handler for consistent error formatting
func WithErrorHandler(handler func(w http.ResponseWriter, r *http.Request, statusCode int, errorResp ErrorResponse)) Option {
	return func(e *Enforcer) {
		e.errorHandler = handler
	}
}

// Enforce returns an HTTP middleware that enforces access control.
func (e *Enforcer) Enforce(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		ctx := r.Context()
		reqLogger := e.logger.With(
			"method", r.Method,
			"path", r.URL.Path,
			"remote_addr", r.RemoteAddr,
		)

		// Extract access request from HTTP request
		accessReq, err := e.requestExtractor.Extract(ctx, r)
		if err != nil {
			reqLogger.ErrorContext(ctx, "request_extraction_failed",
				slog.String("error", err.Error()),
			)
			e.errorHandler(w, r, http.StatusBadRequest, ErrorResponse{
				Error:   "request_extraction_failed",
				Message: "Invalid access request",
			})
			return
		}

		// Evaluate access using the request orchestrator
		accessResp, err := e.orchestrator.EvaluateAccess(ctx, accessReq)
		if err != nil {
			reqLogger.ErrorContext(ctx, "access_evaluation_failed",
				slog.String("error", err.Error()),
				slog.Duration("duration_ms", time.Since(start)),
			)
			e.errorHandler(w, r, http.StatusInternalServerError, ErrorResponse{
				Error:   "access_evaluation_failed",
				Message: "An internal error occurred while evaluating access",
			})
			return
		}

		// Update the request-scoped logger with request ID for correlation
		reqLogger = reqLogger.With("access_request_id", accessResp.RequestID.String())

		// Handle decision
		switch accessResp.Decision {
		case ro.Permit:
			// Handle obligations before allowing access
			if err := e.handleObligations(ctx, accessResp.Obligations, w, r); err != nil {
				reqLogger.ErrorContext(ctx, "obligation_failed",
					slog.String("error", err.Error()),
					slog.Int("obligations_count", len(accessResp.Obligations)),
					slog.Int("advices_count", len(accessResp.Advices)),
					slog.String("decision", string(ro.Permit)),
					slog.Duration("duration_ms", time.Since(start)),
				)
				e.errorHandler(w, r, http.StatusInternalServerError, ErrorResponse{
					Error:   "obligation_failed",
					Message: "An internal error occurred while enforcing obligations",
				})
				return
			}

			// Handle advice (non-blocking)
			if err := e.handleAdvice(ctx, accessResp.Advices, w, r); err != nil {
				reqLogger.WarnContext(ctx, "advice_failed",
					slog.String("error", err.Error()),
					slog.Int("advices_count", len(accessResp.Advices)),
					slog.String("decision", string(ro.Permit)),
				)
			}

			reqLogger.InfoContext(ctx, "access_permitted",
				slog.Int("obligations_count", len(accessResp.Obligations)),
				slog.Int("advices_count", len(accessResp.Advices)),
				slog.String("decision", string(ro.Permit)),
				slog.Duration("duration_ms", time.Since(start)),
			)

			// Allow access to the protected resource
			next.ServeHTTP(w, r)

		case ro.Deny:
			if err := e.handleObligations(ctx, accessResp.Obligations, w, r); err != nil {
				reqLogger.WarnContext(ctx, "obligation_failed_on_deny",
					slog.String("error", err.Error()),
					slog.Int("obligations_count", len(accessResp.Obligations)),
					slog.String("decision", string(ro.Deny)),
				)
			}
			if err := e.handleAdvice(ctx, accessResp.Advices, w, r); err != nil {
				reqLogger.WarnContext(ctx, "advice_failed_on_deny",
					slog.String("error", err.Error()),
					slog.Int("advices_count", len(accessResp.Advices)),
					slog.String("decision", string(ro.Deny)),
				)
			}

			reqLogger.InfoContext(ctx, "access_denied",
				slog.Int("obligations_count", len(accessResp.Obligations)),
				slog.Int("advices_count", len(accessResp.Advices)),
				slog.String("decision", string(ro.Deny)),
				slog.Duration("duration_ms", time.Since(start)),
			)

			e.errorHandler(w, r, http.StatusForbidden, ErrorResponse{
				Error:   "access_denied",
				Message: "You do not have permission to access this resource",
			})

		case ro.NotApplicable:
			reqLogger.InfoContext(ctx, "access_not_applicable",
				slog.String("decision", string(ro.NotApplicable)),
				slog.Int("obligations_count", len(accessResp.Obligations)),
				slog.Int("advices_count", len(accessResp.Advices)),
				slog.Duration("duration_ms", time.Since(start)),
			)

			e.errorHandler(w, r, http.StatusForbidden, ErrorResponse{
				Error:   "access_denied",
				Message: "You do not have permission to access this resource",
			})

		case ro.Indeterminate:
			reqLogger.ErrorContext(ctx, "access_indeterminate",
				slog.String("decision", string(ro.Indeterminate)),
				slog.String("status_code", string(accessResp.Status.Code)),
				slog.String("status_message", accessResp.Status.Message),
				slog.Duration("duration_ms", time.Since(start)),
			)

			e.errorHandler(w, r, http.StatusInternalServerError, ErrorResponse{
				Error:   "indeterminate_decision",
				Message: "An internal error occurred while processing the access decision",
			})
		}
	})
}

// handleObligations processes all obligations that must be fulfilled
func (e *Enforcer) handleObligations(ctx context.Context, obligations []ro.Obligation, w http.ResponseWriter, r *http.Request) error {
	for _, obligation := range obligations {
		handler, exists := e.obligationHandlers[obligation.ID]
		if !exists {
			return fmt.Errorf("no handler registered for obligation ID: %s", obligation.ID)
		}

		if err := handler.Handle(ctx, obligation, w, r); err != nil {
			return fmt.Errorf("obligation handler failed for ID %s: %w", obligation.ID, err)
		}
	}
	return nil
}

// handleAdvice processes all advice (non-blocking suggestions)
func (e *Enforcer) handleAdvice(ctx context.Context, advices []ro.Advice, w http.ResponseWriter, r *http.Request) error {
	for _, advice := range advices {
		handler, exists := e.adviceHandlers[advice.ID]
		if !exists {
			// Advice is optional, so missing handlers are not errors
			continue
		}

		if err := handler.Handle(ctx, advice, w, r); err != nil {
			return fmt.Errorf("advice handler failed for ID %s: %w", advice.ID, err)
		}
	}
	return nil
}

// defaultErrorHandler provides a consistent error response format
func defaultErrorHandler(w http.ResponseWriter, _ *http.Request, statusCode int, errorResp ErrorResponse) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(errorResp)
}
