package middlewares

import (
	"errors"
	"log/slog"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"

	"github.com/CameronXie/access-control-explorer/internal/api/rest/response"
	"github.com/CameronXie/access-control-explorer/internal/enforcer"
	"github.com/CameronXie/access-control-explorer/internal/keyfetcher"
)

const (
	authHeaderMissingMessage       = "authorization header missing"
	invalidAuthHeaderFormatMessage = "invalid authorization header format"
	internalServerErrorMessage     = "internal server error"
	invalidTokenMessage            = "invalid token"
	forbiddenMessage               = "forbidden"
)

// JWTAuthorizationMiddleware handles JWT token authorization, validating tokens and enforcing access policies.
// enforcer is an interface for enforcing access policies.
// publicKeyFetcher is an interface for fetching the public key used to validate JWT tokens.
type JWTAuthorizationMiddleware struct {
	enforcer         enforcer.Enforcer
	publicKeyFetcher keyfetcher.PublicKeyFetcher
	logger           *slog.Logger
}

// Handle processes incoming HTTP requests, applying JWT authorization by validating tokens and enforcing access policies.
func (m *JWTAuthorizationMiddleware) Handle(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			response.JSONErrorResponse(w, http.StatusUnauthorized, authHeaderMissingMessage)
			return
		}

		token, err := extractToken(authHeader)
		if err != nil {
			m.logger.ErrorContext(r.Context(), "failed to extract token", "error", err)
			response.JSONErrorResponse(w, http.StatusUnauthorized, invalidAuthHeaderFormatMessage)
			return
		}

		publicKey, err := m.publicKeyFetcher.FetchPublicKey()
		if err != nil {
			m.logger.ErrorContext(r.Context(), "failed to fetch public key", "error", err)
			response.JSONErrorResponse(w, http.StatusInternalServerError, internalServerErrorMessage)
			return
		}

		claims := new(jwt.MapClaims)
		_, err = jwt.ParseWithClaims(token, claims, func(_ *jwt.Token) (any, error) {
			return publicKey, nil
		})

		if err != nil {
			m.logger.ErrorContext(r.Context(), "failed to parse token", "error", err)
			response.JSONErrorResponse(w, http.StatusUnauthorized, invalidTokenMessage)
			return
		}

		sub, err := claims.GetSubject()
		if sub == "" || err != nil {
			m.logger.ErrorContext(r.Context(), "failed to get subject from token claims")
			response.JSONErrorResponse(w, http.StatusUnauthorized, invalidTokenMessage)
			return
		}

		ok, err := m.enforcer.Enforce(
			r.Context(),
			&enforcer.AccessRequest{
				Subject:  sub,
				Resource: r.URL.Path,
				Action:   r.Method,
			},
		)

		if err != nil || !ok {
			m.logger.ErrorContext(r.Context(), "failed to enforce access policy", "error", err)
			response.JSONErrorResponse(w, http.StatusForbidden, forbiddenMessage)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// extractToken extracts a Bearer token from the Authorization header.
// Returns the extracted token or an error if the header format is invalid.
func extractToken(authHeader string) (string, error) {
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" || parts[1] == "" {
		return "", errors.New("invalid authorization header format")
	}

	return parts[1], nil
}

// NewJWTAuthorizationMiddleware returns a new instance of JWTAuthorizationMiddleware with the given enforcer and public key fetcher.
func NewJWTAuthorizationMiddleware(
	e enforcer.Enforcer,
	publicKeyFetcher keyfetcher.PublicKeyFetcher,
	logger *slog.Logger,
) Middleware {
	return &JWTAuthorizationMiddleware{
		enforcer:         e,
		publicKeyFetcher: publicKeyFetcher,
		logger:           logger,
	}
}
