package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/CameronXie/access-control-explorer/examples/abac/pkg/keyfetcher"
	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const (
	BearerPrefix                         = "bearer"
	DefaultClockSkewTolerance            = 5 * time.Minute
	UserIDContextKey          contextKey = "user_id"
)

// JWTAuthMiddleware handles JWT authentication and sets user ID in context
type JWTAuthMiddleware struct {
	keyFetcher keyfetcher.PublicKeyFetcher
	issuer     string
	audience   string
	clockSkew  time.Duration
}

// JWTConfig holds configuration for JWT authentication middleware
type JWTConfig struct {
	KeyFetcher keyfetcher.PublicKeyFetcher
	Issuer     string
	Audience   string
	ClockSkew  time.Duration // Optional: defaults to DefaultClockSkewTolerance
}

// NewJWTAuthMiddleware creates a new JWT authentication middleware
func NewJWTAuthMiddleware(config JWTConfig) *JWTAuthMiddleware {
	clockSkew := config.ClockSkew
	if clockSkew == 0 {
		clockSkew = DefaultClockSkewTolerance
	}

	return &JWTAuthMiddleware{
		keyFetcher: config.KeyFetcher,
		issuer:     config.Issuer,
		audience:   config.Audience,
		clockSkew:  clockSkew,
	}
}

// Handler returns an HTTP middleware function that validates JWT tokens
func (m *JWTAuthMiddleware) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		userID, err := m.validateJWTAndExtractUserID(r)
		if err != nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		// Set user ID in context
		ctx := context.WithValue(r.Context(), UserIDContextKey, userID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// validateJWTAndExtractUserID validates JWT token and returns user ID (subject)
func (m *JWTAuthMiddleware) validateJWTAndExtractUserID(r *http.Request) (string, error) {
	token, err := m.parseToken(r)
	if err != nil {
		return "", err
	}

	claims, ok := token.Claims.(*jwt.RegisteredClaims)
	if !ok || !token.Valid {
		return "", errors.New("invalid token")
	}

	userID, err := m.validateClaims(claims)
	if err != nil {
		return "", fmt.Errorf("invalid claims: %w", err)
	}

	return userID, nil
}

// parseToken extracts and parses JWT token from request
func (m *JWTAuthMiddleware) parseToken(r *http.Request) (*jwt.Token, error) {
	tokenString, err := extractBearerToken(r)
	if err != nil {
		return nil, err
	}

	key, err := m.keyFetcher.FetchPublicKey()
	if err != nil {
		return nil, fmt.Errorf("failed to fetch public key: %w", err)
	}

	token, err := jwt.ParseWithClaims(tokenString, &jwt.RegisteredClaims{}, func(token *jwt.Token) (any, error) {
		// Ensure token uses RSA signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return key, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return token, nil
}

// validateClaims validates JWT claims and returns subject ID
func (m *JWTAuthMiddleware) validateClaims(claims *jwt.RegisteredClaims) (string, error) {
	if err := m.validateRequiredClaims(claims); err != nil {
		return "", err
	}

	if err := m.validateTiming(claims); err != nil {
		return "", err
	}

	return claims.Subject, nil
}

// validateRequiredClaims validates issuer, audience, and subject claims
func (m *JWTAuthMiddleware) validateRequiredClaims(claims *jwt.RegisteredClaims) error {
	if claims.Subject == "" {
		return errors.New("missing subject claim")
	}

	if claims.Issuer != m.issuer {
		return fmt.Errorf("invalid issuer: got %s, want %s", claims.Issuer, m.issuer)
	}

	if !slices.Contains(claims.Audience, m.audience) {
		return fmt.Errorf("invalid audience: missing %s", m.audience)
	}

	return nil
}

// validateTiming validates expiration and issued-at claims with clock skew tolerance
func (m *JWTAuthMiddleware) validateTiming(claims *jwt.RegisteredClaims) error {
	now := time.Now()

	// Check expiration (required)
	if claims.ExpiresAt == nil {
		return errors.New("missing expiration claim")
	}

	// Check issued-at time with clock skew tolerance (optional claim)
	if claims.IssuedAt != nil && claims.IssuedAt.After(now.Add(m.clockSkew)) {
		return errors.New("token issued too far in future")
	}

	return nil
}

// extractBearerToken extracts JWT token from Authorization header
func extractBearerToken(r *http.Request) (string, error) {
	auth := r.Header.Get("Authorization")
	if auth == "" {
		return "", errors.New("missing authorization header")
	}

	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], BearerPrefix) {
		return "", errors.New("invalid authorization format")
	}

	return parts[1], nil
}

// GetUserIDFromContext extracts user ID from request context
func GetUserIDFromContext(ctx context.Context) (string, bool) {
	userID, ok := ctx.Value(UserIDContextKey).(string)
	return userID, ok
}
