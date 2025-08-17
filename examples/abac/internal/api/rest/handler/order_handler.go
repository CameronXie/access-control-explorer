package handler

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/CameronXie/access-control-explorer/examples/abac/internal/api/rest/middleware"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/domain"
	"github.com/CameronXie/access-control-explorer/examples/abac/internal/repository"
	"github.com/google/uuid"
)

const (
	OrderStatusCreated = "created"
)

// OrderRepository defines the interface for order repository operations
type OrderRepository interface {
	CreateOrder(ctx context.Context, order *domain.Order) error
	GetOrderByID(ctx context.Context, id uuid.UUID) (*domain.Order, error)
}

// OrderHandler handles HTTP requests for order operations
type OrderHandler struct {
	repo   OrderRepository
	logger *slog.Logger
}

// NewOrderHandler creates a new OrderHandler instance
func NewOrderHandler(repo OrderRepository, logger *slog.Logger) *OrderHandler {
	return &OrderHandler{
		repo:   repo,
		logger: logger,
	}
}

// CreateOrderRequest represents the request payload for creating an order
type CreateOrderRequest struct {
	Name       string         `json:"name" validate:"required"`
	Attributes map[string]any `json:"attributes,omitempty"`
}

// CreateOrderResponse represents the response for creating an order
type CreateOrderResponse struct {
	ID         uuid.UUID      `json:"id"`
	Name       string         `json:"name"`
	Attributes map[string]any `json:"attributes"`
}

// CreateOrder handles POST /orders - creates a new order
func (h *OrderHandler) CreateOrder(w http.ResponseWriter, r *http.Request) {
	var req CreateOrderRequest

	// Parse request body
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	// Validate required fields
	if req.Name == "" {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid request", "Name is required")
		return
	}

	// Get user ID from context (set by JWT middleware)
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		h.logger.Error("User ID not found in context")
		WriteErrorResponse(w, http.StatusUnauthorized, "Authentication required", "User authentication is required")
		return
	}

	// Initialize attributes if nil
	if req.Attributes == nil {
		req.Attributes = make(map[string]any)
	}

	// Set owner (user_id) and status in attributes
	req.Attributes["owner"] = userID
	req.Attributes["status"] = OrderStatusCreated

	// Create order domain model
	order := &domain.Order{
		ID:         uuid.New(),
		Name:       req.Name,
		Attributes: req.Attributes,
	}

	// Save to database
	if err := h.repo.CreateOrder(r.Context(), order); err != nil {
		h.logger.Error("Failed to create order", "error", err, "order_name", order.Name, "user_id", userID)
		WriteErrorResponse(
			w,
			http.StatusInternalServerError,
			"Failed to create order",
			"An internal error occurred while processing your request",
		)
		return
	}

	// Return success response
	response := CreateOrderResponse{
		ID:         order.ID,
		Name:       order.Name,
		Attributes: order.Attributes,
	}

	WriteJSONResponse(w, http.StatusCreated, response)
}

// GetOrderByID handles GET /orders/{id} - retrieves an order by ID
func (h *OrderHandler) GetOrderByID(w http.ResponseWriter, r *http.Request) {
	// Extract ID from URL path
	idStr := r.PathValue("id")

	// Parse UUID
	id, err := uuid.Parse(idStr)
	if err != nil {
		WriteErrorResponse(w, http.StatusBadRequest, "Invalid order ID", "ID must be a valid UUID")
		return
	}

	// Get order from database
	order, err := h.repo.GetOrderByID(r.Context(), id)
	if err != nil {
		// Check if it's a not found error using errors.As
		var notFoundErr *repository.NotFoundError
		if errors.As(err, &notFoundErr) {
			h.logger.Warn("Order not found", "order_id", id, "error", err)
			WriteErrorResponse(w, http.StatusNotFound, "Order not found", "The requested order could not be found")
			return
		}

		h.logger.Error("Failed to retrieve order", "order_id", id, "error", err)
		WriteErrorResponse(w, http.StatusInternalServerError, "Failed to retrieve order", "An internal error occurred while retrieving the order")
		return
	}

	// Return order
	WriteJSONResponse(w, http.StatusOK, order)
}
