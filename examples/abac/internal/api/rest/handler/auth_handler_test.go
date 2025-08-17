package handler

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/repository"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// mockUserRepository is a mock implementation of the UserRepository interface.
type mockUserRepository struct {
	mock.Mock
}

func (m *mockUserRepository) GetUserIDByEmail(ctx context.Context, email string) (uuid.UUID, error) {
	args := m.Called(ctx, email)
	return args.Get(0).(uuid.UUID), args.Error(1)
}

// mockPrivateKeyFetcher is a mock implementation of the PrivateKeyFetcher interface.
type mockPrivateKeyFetcher struct {
	mock.Mock
}

func (m *mockPrivateKeyFetcher) FetchPrivateKey() (*rsa.PrivateKey, error) {
	args := m.Called()
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*rsa.PrivateKey), args.Error(1)
}

// Helper function to generate a fake RSA private key.
func generateFakeRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// Helper function to create a test user ID.
func createTestUserID() uuid.UUID {
	return uuid.New()
}

func TestAuthHandler_SignIn(t *testing.T) {
	testUserID := createTestUserID()

	cases := map[string]struct {
		requestBody        string
		mockUserResult     uuid.UUID
		mockUserError      error
		mockKeyError       error
		expectedStatus     int
		expectedMessage    string
		expectedLogMessage string
		expectedLogLevel   slog.Level
	}{
		"should Return 200 and Token on Successful Authentication": {
			requestBody:        `{"email": "test@example.com"}`,
			mockUserResult:     testUserID,
			mockUserError:      nil,
			mockKeyError:       nil,
			expectedStatus:     http.StatusOK,
			expectedLogMessage: "Successful user sign in",
			expectedLogLevel:   slog.LevelInfo,
		},

		"should Return 400 on Invalid Request Body": {
			requestBody:        "invalid",
			mockUserResult:     uuid.Nil,
			mockUserError:      nil,
			mockKeyError:       nil,
			expectedStatus:     http.StatusBadRequest,
			expectedMessage:    "Invalid request format",
			expectedLogMessage: "Invalid request format",
			expectedLogLevel:   slog.LevelWarn,
		},

		"should Return 400 on Missing Email": {
			requestBody:        `{"email": ""}`,
			mockUserResult:     uuid.Nil,
			mockUserError:      nil,
			mockKeyError:       nil,
			expectedStatus:     http.StatusBadRequest,
			expectedMessage:    "Email is required",
			expectedLogMessage: "Sign in attempt with empty email",
			expectedLogLevel:   slog.LevelWarn,
		},

		"should Return 401 on User Not Found": {
			requestBody:        `{"email": "notfound@example.com"}`,
			mockUserResult:     uuid.Nil,
			mockUserError:      &repository.NotFoundError{Resource: "user", Key: "email", Value: "notfound@example.com"},
			mockKeyError:       nil,
			expectedStatus:     http.StatusUnauthorized,
			expectedMessage:    "Authentication failed",
			expectedLogMessage: "Sign in attempt for non-existent user",
			expectedLogLevel:   slog.LevelWarn,
		},

		"should Return 401 on Database Error": {
			requestBody:        `{"email": "error@example.com"}`,
			mockUserResult:     uuid.Nil,
			mockUserError:      errors.New("database connection failed"),
			mockKeyError:       nil,
			expectedStatus:     http.StatusUnauthorized,
			expectedMessage:    "Authentication failed",
			expectedLogMessage: "Failed to retrieve user during sign in",
			expectedLogLevel:   slog.LevelError,
		},

		"should Return 500 on Key Fetch Failure": {
			requestBody:        `{"email": "test@example.com"}`,
			mockUserResult:     testUserID,
			mockUserError:      nil,
			mockKeyError:       errors.New("key fetch failed"),
			expectedStatus:     http.StatusInternalServerError,
			expectedMessage:    "Authentication failed",
			expectedLogMessage: "Failed to generate JWT token",
			expectedLogLevel:   slog.LevelError,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mockUserRepo := new(mockUserRepository)
			mockKeyFetcher := new(mockPrivateKeyFetcher)
			testLogger := newTestLogger()
			logger := testLogger.getLogger()

			config := &AuthConfig{
				KeyFetcher: mockKeyFetcher,
				Issuer:     "test-issuer",
				TokenTTL:   time.Hour,
				Audience:   "test-audience",
			}

			handler := NewAuthHandler(mockUserRepo, config, logger)

			if tc.mockUserResult != uuid.Nil || tc.mockUserError != nil {
				mockUserRepo.On("GetUserIDByEmail", mock.Anything, mock.Anything).Return(tc.mockUserResult, tc.mockUserError)
			}

			var privateKey *rsa.PrivateKey
			if tc.mockKeyError == nil {
				key, err := generateFakeRSAPrivateKey()
				if err != nil {
					t.Fatalf("failed to generate fake RSA private key: %v", err)
				}
				privateKey = key
			}
			if tc.mockUserResult != uuid.Nil && tc.mockUserError == nil {
				mockKeyFetcher.On("FetchPrivateKey").Return(privateKey, tc.mockKeyError)
			}

			w := httptest.NewRecorder()
			r := httptest.NewRequest(
				http.MethodPost,
				"/auth/signin",
				bytes.NewBufferString(tc.requestBody),
			)

			handler.SignIn(w, r)

			// Assert HTTP response
			assert.Equal(t, tc.expectedStatus, w.Code)

			body := w.Body.String()
			if tc.expectedStatus == http.StatusOK {
				assert.Contains(t, body, "token")
				assert.Contains(t, body, "Bearer")
			} else {
				assert.Contains(t, body, tc.expectedMessage)
			}

			// Assert log messages and levels
			if tc.expectedLogMessage != "" {
				assert.NotEmpty(t, testLogger.messages, "Expected log message but no logs were captured")

				// Check if the expected message exists in any of the captured messages
				for i, message := range testLogger.messages {
					assert.Contains(t, message, tc.expectedLogMessage)
					assert.Equal(t, tc.expectedLogLevel, testLogger.levels[i])
				}
			}

			// Verify that mocks were called as expected
			mockUserRepo.AssertExpectations(t)
			mockKeyFetcher.AssertExpectations(t)
			testLogger.reset()
		})
	}
}

func TestAuthHandler_generateJWT(t *testing.T) {
	cases := map[string]struct {
		keyFetchError  error
		expectedError  bool
		validateClaims bool
	}{
		"should Generate Valid JWT Token": {
			keyFetchError:  nil,
			expectedError:  false,
			validateClaims: true,
		},

		"should Return Error on Key Fetch Failure": {
			keyFetchError: errors.New("key fetch failed"),
			expectedError: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			mockKeyFetcher := new(mockPrivateKeyFetcher)
			testLogger := newTestLogger()
			logger := testLogger.getLogger()

			config := &AuthConfig{
				KeyFetcher: mockKeyFetcher,
				Issuer:     "test-issuer",
				TokenTTL:   time.Hour,
				Audience:   "test-audience",
			}

			handler := NewAuthHandler(nil, config, logger)
			userID := createTestUserID()

			var privateKey *rsa.PrivateKey
			if tc.keyFetchError == nil {
				key, err := generateFakeRSAPrivateKey()
				if err != nil {
					t.Fatalf("failed to generate fake RSA private key: %v", err)
				}
				privateKey = key
			}

			mockKeyFetcher.On("FetchPrivateKey").Return(privateKey, tc.keyFetchError)

			token, err := handler.generateJWT(userID)

			if tc.expectedError {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
			}

			mockKeyFetcher.AssertExpectations(t)
		})
	}
}

func TestNewAuthHandler(t *testing.T) {
	mockUserRepo := new(mockUserRepository)
	testLogger := newTestLogger()
	logger := testLogger.getLogger()
	config := &AuthConfig{
		Issuer:   "test-issuer",
		TokenTTL: time.Hour,
		Audience: "test-audience",
	}

	handler := NewAuthHandler(mockUserRepo, config, logger)

	assert.NotNil(t, handler)
	assert.Equal(t, mockUserRepo, handler.userRepo)
	assert.Equal(t, config, handler.config)
	assert.Equal(t, logger, handler.logger)
}
