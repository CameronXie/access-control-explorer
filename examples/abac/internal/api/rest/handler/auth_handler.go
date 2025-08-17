// Package handler provides HTTP handlers for authentication.
// WARNING: This signin handler is for demo purposes only and should NOT be used in production.
// It lacks proper password validation, rate limiting, and other security measures.
package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/repository"
	"github.com/CameronXie/access-control-explorer/examples/abac/pkg/keyfetcher"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// UserRepository defines the interface for user data access
type UserRepository interface {
	GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error)
}

// AuthConfig holds authentication configuration
type AuthConfig struct {
	KeyFetcher keyfetcher.PrivateKeyFetcher
	Issuer     string
	Audience   string
	TokenTTL   time.Duration
}

// AuthHandler handles authentication requests
type AuthHandler struct {
	userRepo UserRepository
	config   *AuthConfig
	logger   *slog.Logger
}

// SignInRequest represents the signin request payload
type SignInRequest struct {
	Email string `json:"email"`
}

// SignInResponse represents the signin response payload
type SignInResponse struct {
	Token     string `json:"token"`
	TokenType string `json:"token_type"`
}

// JWTClaims contains minimal JWT claims for demo purposes
type JWTClaims struct {
	jwt.RegisteredClaims
}

// NewAuthHandler creates a new authentication handler
func NewAuthHandler(userRepo UserRepository, config *AuthConfig, logger *slog.Logger) *AuthHandler {
	return &AuthHandler{
		userRepo: userRepo,
		config:   config,
		logger:   logger,
	}
}

// SignIn handles user signin requests
// WARNING: Demo implementation - lacks password verification and security measures
func (h *AuthHandler) SignIn(w http.ResponseWriter, r *http.Request) {
	// Parse request body
	var req SignInRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.logger.Warn("Invalid request format", "error", err)
		WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Invalid request format")
		return
	}

	// Validate email
	if req.Email == "" {
		h.logger.Warn("Sign in attempt with empty email")
		WriteErrorResponse(w, http.StatusBadRequest, "invalid_request", "Email is required")
		return
	}

	// Look up user ID by email
	userID, err := h.userRepo.GetUserIDByEmail(r.Context(), req.Email)
	if err != nil {
		// Check if it's a not found error
		var notFoundErr *repository.NotFoundError
		if errors.As(err, &notFoundErr) {
			h.logger.Warn("Sign in attempt for non-existent user", "email", req.Email)
		} else {
			h.logger.Error("Failed to retrieve user during sign in", "email", req.Email, "error", err)
		}
		WriteErrorResponse(w, http.StatusUnauthorized, "authentication_failed", "Authentication failed")
		return
	}

	// Generate JWT token
	token, err := h.generateJWT(userID)
	if err != nil {
		h.logger.Error("Failed to generate JWT token", "user_id", userID, "error", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "authentication_failed", "Authentication failed")
		return
	}

	h.logger.Info("Successful user sign in", "user_id", userID, "email", req.Email)

	// Return successful response
	response := SignInResponse{
		Token:     token,
		TokenType: "Bearer",
	}

	WriteJSONResponse(w, http.StatusOK, response)
}

// generateJWT creates a JWT token for the authenticated user
func (h *AuthHandler) generateJWT(userID uuid.UUID) (string, error) {
	// Fetch private key using keyfetcher
	privateKey, err := h.config.KeyFetcher.FetchPrivateKey()
	if err != nil {
		return "", err
	}

	now := time.Now()
	expiresAt := now.Add(h.config.TokenTTL)

	// Create JWT claims with minimal required fields
	claims := JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    h.config.Issuer,
			Subject:   userID.String(),
			Audience:  jwt.ClaimStrings{h.config.Audience},
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
	}

	// Sign and return the token
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	if err != nil {
		return "", err
	}

	return tokenString, nil
}
