package middlewares

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/CameronXie/access-control-explorer/internal/enforcer"
	"github.com/CameronXie/access-control-explorer/internal/keyfetcher"

	"github.com/stretchr/testify/assert"
)

type mockEnforcer struct {
	enforcer.Enforcer
	enforceReturnVal   bool
	enforceReturnError error
}

func (m *mockEnforcer) Enforce(_ context.Context, _ *enforcer.AccessRequest) (bool, error) {
	return m.enforceReturnVal, m.enforceReturnError
}

type mockPublicKeyFetcher struct {
	keyfetcher.PublicKeyFetcher
	publicKey        *rsa.PublicKey
	fetchReturnError error
}

func (m *mockPublicKeyFetcher) FetchPublicKey() (*rsa.PublicKey, error) {
	if m.fetchReturnError != nil {
		return nil, m.fetchReturnError
	}
	return m.publicKey, nil
}

func TestJWTAuthorizationMiddleware_Handle(t *testing.T) {
	privateKey, publicKey, err := generateKeyPair()
	assert.NoError(t, err)

	validToken, err := generateValidToken(privateKey, jwt.MapClaims{
		"sub": "user123",
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	assert.NoError(t, err)

	tokenWithoutSubClaim, err := generateValidToken(privateKey, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	assert.NoError(t, err)

	cases := map[string]struct {
		authorizationHeader string
		expectedStatusCode  int
		expectedMessage     string
		expectedLog         map[string]string
		enforceReturnVal    bool
		enforceReturnError  error
		fetchReturnError    error
	}{
		"HappyPath": {
			authorizationHeader: fmt.Sprintf("Bearer %s", validToken),
			expectedStatusCode:  http.StatusOK,
			enforceReturnVal:    true,
		},
		"InvalidToken": {
			authorizationHeader: "Bearer invalidtoken",
			expectedStatusCode:  http.StatusUnauthorized,
			expectedMessage:     invalidTokenMessage,
			expectedLog: map[string]string{
				"level": "ERROR",
				"msg":   "failed to parse token",
				"error": "token is malformed: token contains an invalid number of segments",
			},
		},
		"InvalidTokenFormat": {
			authorizationHeader: validToken,
			expectedStatusCode:  http.StatusUnauthorized,
			expectedMessage:     invalidAuthHeaderFormatMessage,
			expectedLog: map[string]string{
				"level": "ERROR",
				"msg":   "failed to extract token",
				"error": "invalid authorization header format",
			},
		},
		"AuthorizationHeaderMissing": {
			expectedStatusCode: http.StatusUnauthorized,
			expectedMessage:    authHeaderMissingMessage,
		},
		"SubClaimMissing": {
			authorizationHeader: fmt.Sprintf("Bearer %s", tokenWithoutSubClaim),
			expectedStatusCode:  http.StatusUnauthorized,
			expectedMessage:     invalidTokenMessage,
			expectedLog: map[string]string{
				"level": "ERROR",
				"msg":   "failed to get subject from token claims",
			},
		},
		"EnforcerError": {
			authorizationHeader: fmt.Sprintf("Bearer %s", validToken),
			expectedStatusCode:  http.StatusForbidden,
			enforceReturnError:  errors.New("some error"),
			expectedMessage:     forbiddenMessage,
			expectedLog: map[string]string{
				"level": "ERROR",
				"msg":   "failed to enforce access policy",
				"error": "some error",
			},
		},
		"FetchPublicKeyError": {
			authorizationHeader: fmt.Sprintf("Bearer %s", validToken),
			expectedStatusCode:  http.StatusInternalServerError,
			fetchReturnError:    errors.New("some error"),
			expectedMessage:     internalServerErrorMessage,
			expectedLog: map[string]string{
				"level": "ERROR",
				"msg":   "failed to fetch public key",
				"error": "some error",
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			e := &mockEnforcer{enforceReturnVal: tc.enforceReturnVal, enforceReturnError: tc.enforceReturnError}
			k := &mockPublicKeyFetcher{publicKey: publicKey, fetchReturnError: tc.fetchReturnError}
			h := slog.NewJSONHandler(&buf, nil)
			middleware := NewJWTAuthorizationMiddleware(e, k, slog.New(h))

			request := httptest.NewRequest(http.MethodGet, "/", http.NoBody)
			if tc.authorizationHeader != "" {
				request.Header.Set("Authorization", tc.authorizationHeader)
			}
			w := httptest.NewRecorder()

			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusOK)
			})
			middleware.Handle(nextHandler).ServeHTTP(w, request)

			assert.Equal(t, tc.expectedStatusCode, w.Code)
			if tc.expectedMessage != "" {
				assert.Equal(t, fmt.Sprintf("{\"error\":%q}\n", tc.expectedMessage), w.Body.String())
			}

			if tc.expectedLog != nil {
				log := buf.String()
				for k, v := range tc.expectedLog {
					assert.Contains(t, log, fmt.Sprintf("%q:%q", k, v))
				}
			}
		})
	}
}

func TestExtractToken(t *testing.T) {
	cases := map[string]struct {
		input    string
		expected string
		hasError bool
	}{
		"valid token":   {input: "Bearer tokenvalue", expected: "tokenvalue", hasError: false},
		"invalid token": {input: "tokenvalue", expected: "", hasError: true},
		"empty header":  {input: "", expected: "", hasError: true},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			result, err := extractToken(tc.input)
			assert.Equal(t, tc.expected, result)
			if tc.hasError {
				assert.NotNil(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}

func generateKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func generateValidToken(privateKey *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}
