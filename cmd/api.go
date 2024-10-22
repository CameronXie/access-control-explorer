package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	_ "github.com/go-sql-driver/mysql"

	"github.com/CameronXie/access-control-explorer/internal/api/rest"
	"github.com/CameronXie/access-control-explorer/internal/api/rest/handlers"
	"github.com/CameronXie/access-control-explorer/internal/api/rest/middlewares"
	"github.com/CameronXie/access-control-explorer/internal/authn"
	"github.com/CameronXie/access-control-explorer/internal/keyfetcher"
	"github.com/CameronXie/access-control-explorer/internal/version"
)

const (
	PrivateKeyEnv  = "PRIVATE_KEY_BASE64"
	PublicKeyEnv   = "PUBLIC_KEY_BASE64"
	NumOfResources = 5

	ReadTimeout  = 5 * time.Second
	WriteTimeout = 10 * time.Second
	IdleTimeout  = 120 * time.Second

	PortNumber = 8080
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With(
		slog.String("version", version.Version),
	)

	enforcer, err := newEnforcer(logger)
	if err != nil {
		log.Fatal(err)
	}

	mux := rest.NewMuxWithHandlers(
		&rest.RouterConfig{
			SignInHandler: handlers.NewSignInHandler(
				authn.NewHardcodedAuthenticator(map[string]string{
					"user1@example.com": "password",
					"user2@example.com": "password",
				}),
				keyfetcher.FromBase64Env(PrivateKeyEnv),
				logger,
			),
			ResourceHandler: handlers.NewHardcodedResourcesHandler(generateHardcodedResources(NumOfResources)),
			AuthorisationMiddleware: middlewares.NewJWTAuthorizationMiddleware(
				enforcer,
				keyfetcher.FromBase64Env(PublicKeyEnv),
				logger,
			),
		},
	)

	server := &http.Server{
		Addr:         fmt.Sprintf(":%v", PortNumber),
		Handler:      mux,
		ReadTimeout:  ReadTimeout,
		WriteTimeout: WriteTimeout,
		IdleTimeout:  IdleTimeout,
	}

	log.Printf("Starting server on :%v (Version: %s)\n", PortNumber, version.Version)
	log.Fatal(server.ListenAndServe())
}

// generateHardcodedResources generates a slice of hardcoded Resource objects with specified length n.
func generateHardcodedResources(n int) []handlers.Resource {
	resources := make([]handlers.Resource, 0, n)
	for i := 1; i <= n; i++ {
		resources = append(resources, handlers.Resource{
			ID:     i,
			Name:   fmt.Sprintf("Resource %d", i),
			Active: i%2 == 1,
		})
	}

	return resources
}
