package advice

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	ro "github.com/CameronXie/access-control-explorer/abac/requestorchestrator"
)

// CacheHintAdviceHandler sets a response header with the suggested TTL (in seconds)
// read from the "ttl_seconds" attribute in the "cache_hint" advice.
// By default, it writes "X-ABAC-Decision-TTL" header. You can override the header
// name via the constructor.
type CacheHintAdviceHandler struct {
	HeaderName string
}

// NewCacheHintAdviceHandler creates a new CacheHintAdviceHandler.
// If headerName is empty, it defaults to "X-ABAC-Decision-TTL".
func NewCacheHintAdviceHandler(headerName string) *CacheHintAdviceHandler {
	if headerName == "" {
		headerName = "X-ABAC-Decision-TTL"
	}
	return &CacheHintAdviceHandler{HeaderName: headerName}
}

func (h *CacheHintAdviceHandler) Handle(_ context.Context, advice ro.Advice, w http.ResponseWriter, _ *http.Request) error {
	// Expect attribute "ttl_seconds"
	raw, ok := advice.Attributes["ttl_seconds"]
	if !ok {
		return fmt.Errorf("cache_hint advice missing 'ttl_seconds' attribute")
	}

	ttl, err := toInt(raw)
	if err != nil {
		return fmt.Errorf("cache_hint invalid 'ttl_seconds': %w", err)
	}
	if ttl <= 0 {
		return fmt.Errorf("cache_hint 'ttl_seconds' must be > 0, got %d", ttl)
	}

	w.Header().Set(h.HeaderName, strconv.Itoa(ttl))
	return nil
}

func toInt(v any) (int, error) {
	switch t := v.(type) {
	case int:
		return t, nil
	case int32:
		return int(t), nil
	case int64:
		return int(t), nil
	case float32:
		return int(t), nil
	case float64:
		return int(t), nil
	case string:
		n, err := strconv.Atoi(t)
		if err != nil {
			return 0, fmt.Errorf("not a number: %v", t)
		}
		return n, nil
	default:
		return 0, fmt.Errorf("unsupported type %T", v)
	}
}
