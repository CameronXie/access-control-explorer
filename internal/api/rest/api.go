package rest

import (
	"net/http"

	"github.com/CameronXie/access-control-explorer/internal/api/rest/middlewares"
)

type RouterConfig struct {
	SignInHandler           http.Handler
	ResourceHandler         http.Handler
	AuthorisationMiddleware middlewares.Middleware
}

// NewMuxWithHandlers initializes a new HTTP mux with routes defined by the given RouterConfig.
func NewMuxWithHandlers(cfg *RouterConfig) *http.ServeMux {
	router := http.NewServeMux()

	router.Handle("POST /auth/signin", cfg.SignInHandler)
	router.Handle("GET /api/resources", cfg.AuthorisationMiddleware.Handle(cfg.ResourceHandler))

	return router
}
