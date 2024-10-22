package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/CameronXie/access-control-explorer/internal/api/rest/response"
	"github.com/CameronXie/access-control-explorer/internal/authn"
	"github.com/CameronXie/access-control-explorer/internal/keyfetcher"
)

const (
	tokenExpirationDuration          = time.Hour
	invalidRequestBodyMessage        = "invalid request body"
	invalidUsernameOrPasswordMessage = "invalid username or password"
	internalServerErrorMessage       = "internal server error"
)

type SignInRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// SignInHandler processes user sign-in requests, authenticates credentials, and generates JWT tokens.
type SignInHandler struct {
	authenticator     authn.Authenticator
	privateKeyFetcher keyfetcher.PrivateKeyFetcher
	logger            *slog.Logger
}

// ServeHTTP handles HTTP requests for user sign-in, authenticates users and generates JWT tokens on successful login.
func (h *SignInHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	req := new(SignInRequest)
	decodeErr := json.NewDecoder(r.Body).Decode(req)
	if decodeErr != nil {
		response.JSONErrorResponse(w, http.StatusBadRequest, invalidRequestBodyMessage)
		return
	}

	h.logger.With("username", req.Username)
	authenticatedUser, authError := h.authenticator.Authenticate(req.Username, req.Password)
	if authError != nil {
		h.logger.ErrorContext(r.Context(), "failed to authenticate user", "error", authError)
		response.JSONErrorResponse(w, http.StatusUnauthorized, invalidUsernameOrPasswordMessage)
		return
	}

	token, jwtError := h.generateJWT(authenticatedUser.Username)
	if jwtError != nil {
		h.logger.ErrorContext(r.Context(), "failed to generate JWT", "error", jwtError)
		response.JSONErrorResponse(w, http.StatusInternalServerError, internalServerErrorMessage)
		return
	}

	response.JSONResponse(w, http.StatusOK, map[string]string{"token": token})
}

// generateJWT generates a JSON Web Token (JWT) for the given username with RS512 signing method and 1-hour expiration.
func (h *SignInHandler) generateJWT(username string) (string, error) {
	token := jwt.NewWithClaims(
		jwt.SigningMethodRS512,
		jwt.MapClaims{
			"sub": username,
			"iat": time.Now().Unix(),
			"exp": time.Now().Add(tokenExpirationDuration).Unix(),
		},
	)

	privateKey, jwtError := h.privateKeyFetcher.FetchPrivateKey()
	if jwtError != nil {
		return "", jwtError
	}

	tokenString, signError := token.SignedString(privateKey)
	if signError != nil {
		return "", signError
	}

	return tokenString, nil
}

// NewSignInHandler creates a new HTTP handler for user sign-in, using the provided authenticator and private key fetcher.
func NewSignInHandler(
	authenticator authn.Authenticator,
	privateKeyFetcher keyfetcher.PrivateKeyFetcher,
	logger *slog.Logger,
) http.Handler {
	return &SignInHandler{
		authenticator:     authenticator,
		privateKeyFetcher: privateKeyFetcher,
		logger:            logger,
	}
}
