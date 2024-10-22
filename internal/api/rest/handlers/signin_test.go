package handlers

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/CameronXie/access-control-explorer/internal/authn"
)

// mockAuthenticator is a mock implementation of the Authenticator interface.
type mockAuthenticator struct {
	mock.Mock
}

func (m *mockAuthenticator) Authenticate(username, password string) (*authn.User, error) {
	args := m.Called(username, password)
	return args.Get(0).(*authn.User), args.Error(1)
}

// mockPrivateKeyFetcher is a mock implementation of the PrivateKeyFetcher interface.
type mockPrivateKeyFetcher struct {
	mock.Mock
}

func (m *mockPrivateKeyFetcher) FetchPrivateKey() (*rsa.PrivateKey, error) {
	args := m.Called()
	return args.Get(0).(*rsa.PrivateKey), args.Error(1)
}

// Helper function to generate a fake RSA private key.
func generateFakeRSAPrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

func TestSignInHandler_ServeHTTP(t *testing.T) {
	cases := map[string]struct {
		requestBody     string
		mockAuthResult  *authn.User
		mockAuthError   error
		mockKeyError    error
		expectedStatus  int
		expectedMessage string
		expectedLog     map[string]string
	}{
		"Should Return 200 and Token on Successful Authentication": {
			requestBody:    `{"username": "testuser", "password": "password"}`,
			mockAuthResult: &authn.User{Username: "testuser"},
			mockAuthError:  nil,
			mockKeyError:   nil,
			expectedStatus: http.StatusOK,
		},
		"Should Return 400 on Invalid Request Body": {
			requestBody:     "invalid",
			mockAuthResult:  nil,
			mockAuthError:   nil,
			mockKeyError:    nil,
			expectedStatus:  http.StatusBadRequest,
			expectedMessage: invalidRequestBodyMessage,
		},
		"Should Return 401 on Authentication Failure": {
			requestBody:     `{"username": "testuser", "password": "wrongpassword"}`,
			mockAuthResult:  nil,
			mockAuthError:   errors.New("auth failed"),
			mockKeyError:    nil,
			expectedStatus:  http.StatusUnauthorized,
			expectedMessage: invalidUsernameOrPasswordMessage,
			expectedLog: map[string]string{
				"level": "ERROR",
				"msg":   "failed to authenticate user",
				"error": "auth failed",
			},
		},
		"Should Return 500 on Key Fetch Failure": {
			requestBody:     `{"username": "testuser", "password": "password"}`,
			mockAuthResult:  &authn.User{Username: "testuser"},
			mockAuthError:   nil,
			mockKeyError:    errors.New("key fetch failed"),
			expectedStatus:  http.StatusInternalServerError,
			expectedMessage: internalServerErrorMessage,
			expectedLog: map[string]string{
				"level": "ERROR",
				"msg":   "failed to generate JWT",
				"error": "key fetch failed",
			},
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			var buf bytes.Buffer
			mockAuth := new(mockAuthenticator)
			mockKeyFetcher := new(mockPrivateKeyFetcher)
			logHandler := slog.NewJSONHandler(&buf, nil)
			handler := NewSignInHandler(mockAuth, mockKeyFetcher, slog.New(logHandler))

			mockAuth.On("Authenticate", mock.Anything, mock.Anything).Return(tc.mockAuthResult, tc.mockAuthError)

			var privateKey *rsa.PrivateKey
			if tc.mockKeyError == nil {
				key, err := generateFakeRSAPrivateKey()
				if err != nil {
					t.Fatalf("failed to generate fake RSA private key: %v", err)
				}
				privateKey = key
			}

			mockKeyFetcher.On("FetchPrivateKey").Return(privateKey, tc.mockKeyError)

			w := httptest.NewRecorder()
			handler.ServeHTTP(
				w,
				httptest.NewRequest(
					http.MethodPost,
					"/",
					bytes.NewBufferString(tc.requestBody),
				),
			)

			assert.Equal(t, tc.expectedStatus, w.Code)

			if tc.expectedLog != nil {
				log := buf.String()
				for k, v := range tc.expectedLog {
					assert.Contains(t, log, fmt.Sprintf("%q:%q", k, v))
				}
			}

			body := w.Body.String()
			if tc.expectedStatus == http.StatusOK {
				assert.Contains(t, body, "token")
				return
			}

			assert.Contains(t, body, tc.expectedMessage)
		})
	}
}
