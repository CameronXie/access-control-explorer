package keyfetcher

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFrom_FetchPublicKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	assert.NoError(t, err)

	pubKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	cases := map[string]struct {
		envKey     string
		envValue   string
		expectedPk *rsa.PublicKey
		expectedEr string
	}{
		"success": {
			envKey:     "TEST_PUBLIC_KEY",
			envValue:   base64.StdEncoding.EncodeToString(pubKeyPem),
			expectedPk: &privateKey.PublicKey,
		},
		"failure": {
			envKey:     "NON_EXISTANT_KEY",
			expectedEr: "key is not found",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			os.Setenv(tc.envKey, tc.envValue)

			fetcher := FromBase64Env(tc.envKey)
			pk, err := fetcher.FetchPublicKey()

			if tc.expectedEr != "" {
				assert.EqualError(t, err, tc.expectedEr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedPk, pk)
			os.Unsetenv(tc.envKey)
		})
	}
}

func TestFrom_FetchPrivateKey(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	assert.NoError(t, err)

	privKeyPem := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privKeyBytes,
	})

	cases := map[string]struct {
		envKey     string
		envValue   string
		expectedPk *rsa.PrivateKey
		expectedEr string
	}{
		"success": {
			envKey:     "TEST_PRIVATE_KEY",
			envValue:   base64.StdEncoding.EncodeToString(privKeyPem),
			expectedPk: privateKey,
		},
		"failure": {
			envKey:     "NON_EXISTANT_KEY",
			expectedEr: "key is not found",
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			os.Setenv(tc.envKey, tc.envValue)

			fetcher := FromBase64Env(tc.envKey)
			pk, err := fetcher.FetchPrivateKey()

			if tc.expectedEr != "" {
				assert.EqualError(t, err, tc.expectedEr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expectedPk, pk)
			os.Unsetenv(tc.envKey)
		})
	}
}
