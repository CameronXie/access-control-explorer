package obligation

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
)

// AuditLogHandler logs messages based on PDP obligations
type AuditLogHandler struct {
	logger *slog.Logger
}

// AuditLogAttributes defines the fixed structure of audit log obligations
type AuditLogAttributes struct {
	Level   string `json:"level"`   // Log level (DEBUG, INFO, WARN, ERROR)
	Message string `json:"message"` // Message to be logged
}

// NewAuditLogHandler creates a new audit log handler
func NewAuditLogHandler(logger *slog.Logger) *AuditLogHandler {
	return &AuditLogHandler{logger: logger}
}

// Handle processes audit logging obligations from PDP
func (h *AuditLogHandler) Handle(ctx context.Context, obligation ro.Obligation, _ http.ResponseWriter, _ *http.Request) error {
	var attrs AuditLogAttributes
	if err := parseAttributes(obligation.Attributes, &attrs); err != nil {
		return fmt.Errorf("invalid audit log attributes: %w", err)
	}

	h.logger.LogAttrs(ctx, parseLogLevel(attrs.Level), attrs.Message,
		slog.String("obligation_id", obligation.ID))

	return nil
}

// parseAttributes converts and validates obligation attributes
func parseAttributes(attrs map[string]any, result *AuditLogAttributes) error {
	data, err := json.Marshal(attrs)
	if err != nil {
		return fmt.Errorf("failed to marshal attributes: %w", err)
	}

	if err := json.Unmarshal(data, result); err != nil {
		return fmt.Errorf("failed to unmarshal attributes: %w", err)
	}

	if result.Level == "" {
		return fmt.Errorf("level is required")
	}
	if result.Message == "" {
		return fmt.Errorf("message is required")
	}

	return nil
}

// parseLogLevel converts string level to slog.Level
func parseLogLevel(level string) slog.Level {
	switch strings.ToUpper(level) {
	case "DEBUG":
		return slog.LevelDebug
	case "WARN":
		return slog.LevelWarn
	case "ERROR":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
