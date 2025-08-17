package middleware

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

// mockKeyFetcher is a mock implementation of keyfetcher.PublicKeyFetcher
type mockKeyFetcher struct {
	mock.Mock
}

func (m *mockKeyFetcher) FetchPublicKey() (*rsa.PublicKey, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PublicKey), args.Error(1)
}

// Test helper functions
func generateTestKeyPair(t *testing.T) (*rsa.PrivateKey, *rsa.PublicKey) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return privateKey, &privateKey.PublicKey
}

func createTestToken(t *testing.T, privateKey *rsa.PrivateKey, claims *jwt.RegisteredClaims) string {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tokenString, err := token.SignedString(privateKey)
	require.NoError(t, err)
	return tokenString
}

func createValidClaims(issuer, audience, subject string) *jwt.RegisteredClaims {
	return &jwt.RegisteredClaims{
		Issuer:    issuer,
		Subject:   subject,
		Audience:  []string{audience},
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}
}

func TestNewJWTAuthMiddleware(t *testing.T) {
	testCases := map[string]struct {
		config JWTConfig
		want   time.Duration
	}{
		"should use custom clock skew when provided": {
			config: JWTConfig{
				KeyFetcher: &mockKeyFetcher{},
				Issuer:     "test-issuer",
				Audience:   "test-audience",
				ClockSkew:  10 * time.Minute,
			},
			want: 10 * time.Minute,
		},
		"should use default clock skew when not provided": {
			config: JWTConfig{
				KeyFetcher: &mockKeyFetcher{},
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			},
			want: DefaultClockSkewTolerance,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			middleware := NewJWTAuthMiddleware(tc.config)
			assert.Equal(t, tc.want, middleware.clockSkew)
			assert.Equal(t, tc.config.Issuer, middleware.issuer)
			assert.Equal(t, tc.config.Audience, middleware.audience)
		})
	}
}

func TestJWTAuthMiddleware_Handler(t *testing.T) {
	privateKey, publicKey := generateTestKeyPair(t)
	now := time.Now()

	testCases := map[string]struct {
		setupRequest   func() *http.Request
		setupMock      func(*mockKeyFetcher)
		expectedStatus int
		expectedUserID string
	}{
		"should authenticate successfully with valid token": {
			setupRequest: func() *http.Request {
				claims := createValidClaims("test-issuer", "test-audience", "userId")
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusOK,
			expectedUserID: "userId",
		},
		"should return unauthorized when authorization header is missing": {
			setupRequest: func() *http.Request {
				return httptest.NewRequest("GET", "/test", http.NoBody)
			},
			setupMock: func(_ *mockKeyFetcher) {
				// No mock setup needed
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when authorization format is invalid": {
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "InvalidFormat token")
				return req
			},
			setupMock: func(_ *mockKeyFetcher) {
				// No mock setup needed
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when key fetcher fails": {
			setupRequest: func() *http.Request {
				claims := createValidClaims("test-issuer", "test-audience", "user123")
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(nil, errors.New("key fetch error"))
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when token format is invalid": {
			setupRequest: func() *http.Request {
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer invalid.token.format")
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when token uses wrong signing method": {
			setupRequest: func() *http.Request {
				// Create token with HMAC instead of RSA
				claims := createValidClaims("test-issuer", "test-audience", "user123")
				token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
				tokenString, err := token.SignedString([]byte("secret"))
				require.NoError(t, err)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+tokenString)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when token is expired": {
			setupRequest: func() *http.Request {
				claims := &jwt.RegisteredClaims{
					Issuer:    "test-issuer",
					Subject:   "user123",
					Audience:  []string{"test-audience"},
					ExpiresAt: jwt.NewNumericDate(now.Add(-time.Hour)), // Expired
					IssuedAt:  jwt.NewNumericDate(now.Add(-2 * time.Hour)),
				}
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when issuer is invalid": {
			setupRequest: func() *http.Request {
				claims := createValidClaims("wrong-issuer", "test-audience", "user123")
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when audience is invalid": {
			setupRequest: func() *http.Request {
				claims := createValidClaims("test-issuer", "wrong-audience", "user123")
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when subject is missing": {
			setupRequest: func() *http.Request {
				claims := &jwt.RegisteredClaims{
					Issuer:    "test-issuer",
					Subject:   "", // Empty subject
					Audience:  []string{"test-audience"},
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					IssuedAt:  jwt.NewNumericDate(now),
				}
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when expiration is missing": {
			setupRequest: func() *http.Request {
				claims := &jwt.RegisteredClaims{
					Issuer:   "test-issuer",
					Subject:  "user123",
					Audience: []string{"test-audience"},
					// ExpiresAt: nil, // Missing expiration
					IssuedAt: jwt.NewNumericDate(now),
				}
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should return unauthorized when token is issued too far in future": {
			setupRequest: func() *http.Request {
				claims := &jwt.RegisteredClaims{
					Issuer:    "test-issuer",
					Subject:   "user123",
					Audience:  []string{"test-audience"},
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					IssuedAt:  jwt.NewNumericDate(now.Add(10 * time.Minute)), // Beyond tolerance
				}
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		"should accept token issued in future within tolerance": {
			setupRequest: func() *http.Request {
				claims := &jwt.RegisteredClaims{
					Issuer:    "test-issuer",
					Subject:   "user123",
					Audience:  []string{"test-audience"},
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					IssuedAt:  jwt.NewNumericDate(now.Add(1 * time.Minute)), // Within tolerance
				}
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusOK,
			expectedUserID: "user123",
		},
		"should accept token with multiple audiences containing valid one": {
			setupRequest: func() *http.Request {
				claims := &jwt.RegisteredClaims{
					Issuer:    "test-issuer",
					Subject:   "user123",
					Audience:  []string{"other-audience", "test-audience", "third-audience"},
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					IssuedAt:  jwt.NewNumericDate(now),
				}
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusOK,
			expectedUserID: "user123",
		},
		"should accept token without issued at claim": {
			setupRequest: func() *http.Request {
				claims := &jwt.RegisteredClaims{
					Issuer:    "test-issuer",
					Subject:   "user123",
					Audience:  []string{"test-audience"},
					ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
					// IssuedAt: nil, // No issued at claim
				}
				token := createTestToken(t, privateKey, claims)
				req := httptest.NewRequest("GET", "/test", http.NoBody)
				req.Header.Set("Authorization", "Bearer "+token)
				return req
			},
			setupMock: func(m *mockKeyFetcher) {
				m.On("FetchPublicKey").Return(publicKey, nil)
			},
			expectedStatus: http.StatusOK,
			expectedUserID: "user123",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			mockKeyFetcher := &mockKeyFetcher{}
			tc.setupMock(mockKeyFetcher)

			middleware := NewJWTAuthMiddleware(JWTConfig{
				KeyFetcher: mockKeyFetcher,
				Issuer:     "test-issuer",
				Audience:   "test-audience",
			})

			// Create a test handler that captures the user ID from context
			var capturedUserID string
			nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if userID, ok := GetUserIDFromContext(r.Context()); ok {
					capturedUserID = userID
				}
				w.WriteHeader(http.StatusOK)
			})

			handler := middleware.Handler(nextHandler)
			req := tc.setupRequest()
			rr := httptest.NewRecorder()

			handler.ServeHTTP(rr, req)

			assert.Equal(t, tc.expectedStatus, rr.Code)
			if tc.expectedStatus == http.StatusOK {
				assert.Equal(t, tc.expectedUserID, capturedUserID)
			}

			mockKeyFetcher.AssertExpectations(t)
		})
	}
}

func TestExtractBearerToken(t *testing.T) {
	testCases := map[string]struct {
		authorization string
		expectedToken string
		expectedError bool
	}{
		"should extract token from valid bearer header": {
			authorization: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		"should extract token from lowercase bearer header": {
			authorization: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		"should extract token from mixed case bearer header": {
			authorization: "BeArEr eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
			expectedToken: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
		},
		"should return error when authorization header is missing": {
			authorization: "",
			expectedError: true,
		},
		"should return error when bearer token has no space": {
			authorization: "Bearertoken",
			expectedError: true,
		},
		"should return error when authorization uses wrong scheme": {
			authorization: "Basic dXNlcjpwYXNz",
			expectedError: true,
		},
		"should return error when only bearer is provided": {
			authorization: "Bearer",
			expectedError: true,
		},
		"should handle token with spaces in it": {
			authorization: "Bearer token extra",
			expectedToken: "token extra",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest("GET", "/test", http.NoBody)
			if tc.authorization != "" {
				req.Header.Set("Authorization", tc.authorization)
			}

			token, err := extractBearerToken(req)

			if tc.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tc.expectedToken, token)
			}
		})
	}
}

func TestGetUserIDFromContext(t *testing.T) {
	testCases := map[string]struct {
		setupCtx   func() context.Context
		expectedID string
		expectedOK bool
	}{
		"should extract user ID from context successfully": {
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), UserIDContextKey, "user123")
			},
			expectedID: "user123",
			expectedOK: true,
		},
		"should return false when user ID is missing from context": {
			setupCtx: func() context.Context {
				return context.Background()
			},
			expectedID: "",
			expectedOK: false,
		},
		"should return false when context value has wrong type": {
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), UserIDContextKey, 123)
			},
			expectedID: "",
			expectedOK: false,
		},
		"should return false when context has different key": {
			setupCtx: func() context.Context {
				return context.WithValue(context.Background(), contextKey("different_key"), "user123")
			},
			expectedID: "",
			expectedOK: false,
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			ctx := tc.setupCtx()
			userID, ok := GetUserIDFromContext(ctx)
			assert.Equal(t, tc.expectedID, userID)
			assert.Equal(t, tc.expectedOK, ok)
		})
	}
}

func TestJWTAuthMiddleware_validateRequiredClaims(t *testing.T) {
	middleware := NewJWTAuthMiddleware(JWTConfig{
		KeyFetcher: &mockKeyFetcher{},
		Issuer:     "test-issuer",
		Audience:   "test-audience",
	})

	testCases := map[string]struct {
		claims        *jwt.RegisteredClaims
		expectedError string
	}{
		"should validate claims successfully": {
			claims: &jwt.RegisteredClaims{
				Subject:  "user123",
				Issuer:   "test-issuer",
				Audience: []string{"test-audience"},
			},
		},
		"should return error when subject is missing": {
			claims: &jwt.RegisteredClaims{
				Issuer:   "test-issuer",
				Audience: []string{"test-audience"},
			},
			expectedError: "missing subject claim",
		},
		"should return error when issuer is wrong": {
			claims: &jwt.RegisteredClaims{
				Subject:  "user123",
				Issuer:   "wrong-issuer",
				Audience: []string{"test-audience"},
			},
			expectedError: "invalid issuer",
		},
		"should return error when audience is wrong": {
			claims: &jwt.RegisteredClaims{
				Subject:  "user123",
				Issuer:   "test-issuer",
				Audience: []string{"wrong-audience"},
			},
			expectedError: "invalid audience",
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			err := middleware.validateRequiredClaims(tc.claims)
			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestJWTAuthMiddleware_validateTiming(t *testing.T) {
	middleware := NewJWTAuthMiddleware(JWTConfig{
		KeyFetcher: &mockKeyFetcher{},
		Issuer:     "test-issuer",
		Audience:   "test-audience",
		ClockSkew:  5 * time.Minute,
	})

	now := time.Now()

	testCases := map[string]struct {
		claims        *jwt.RegisteredClaims
		expectedError string
	}{
		"should validate timing successfully": {
			claims: &jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now.Add(-time.Minute)),
			},
		},
		"should return error when expiration is missing": {
			claims: &jwt.RegisteredClaims{
				IssuedAt: jwt.NewNumericDate(now),
			},
			expectedError: "missing expiration claim",
		},
		"should return error when token is issued too far in future": {
			claims: &jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
				IssuedAt:  jwt.NewNumericDate(now.Add(10 * time.Minute)),
			},
			expectedError: "token issued too far in future",
		},
		"should accept token without issued at claim": {
			claims: &jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			},
		},
	}

	for name, tc := range testCases {
		t.Run(name, func(t *testing.T) {
			err := middleware.validateTiming(tc.claims)
			if tc.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tc.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
