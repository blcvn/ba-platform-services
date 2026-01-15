package helper

import (
	"context"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type utilities struct {
}

func NewUtilities() *utilities {
	return &utilities{}
}

func (u *utilities) GetHeaderKey(ctx context.Context, key string) string {
	if md, exists := metadata.FromIncomingContext(ctx); exists {
		values := md.Get(key)
		if len(values) == 0 {
			return ""
		}
		return values[0]
	}
	return ""
}

func (u *utilities) GetHeaderListString(ctx context.Context, key string) []string {
	if md, exists := metadata.FromIncomingContext(ctx); exists {
		values := md.Get(key)
		return values
	}
	return []string{}
}

// GetQueryParam retrieves a query parameter from the gRPC metadata
// When using grpc-gateway, HTTP query parameters are automatically converted to gRPC metadata
// Note: grpc-gateway may convert keys to lowercase
func (u *utilities) GetQueryParam(ctx context.Context, key string) string {
	if md, exists := metadata.FromIncomingContext(ctx); exists {
		// Try the original key first
		values := md.Get(key)
		if len(values) > 0 {
			return values[0]
		}
		// Try lowercase version (grpc-gateway convention)
		values = md.Get(strings.ToLower(key))
		if len(values) > 0 {
			return values[0]
		}
	}
	return ""
}

// SetResponseHeader sets a single response header in the gRPC context
func (u *utilities) SetResponseHeader(ctx context.Context, key, value string) error {
	return grpc.SetHeader(ctx, metadata.Pairs(key, value))
}

// SetResponseHeaders sets multiple values for a response header in the gRPC context
func (u *utilities) SetResponseHeaders(ctx context.Context, key string, values []string) error {
	pairs := make([]string, 0, len(values)*2)
	for _, value := range values {
		pairs = append(pairs, key, value)
	}
	return grpc.SetHeader(ctx, metadata.Pairs(pairs...))
}

// GetClientIP extracts the client IP address from gRPC metadata
// Checks X-Forwarded-For and X-Real-IP headers (common in proxy/gateway setups)
func (u *utilities) GetClientIP(ctx context.Context) string {
	// Try X-Forwarded-For first (may contain multiple IPs, take the first one)
	if md, exists := metadata.FromIncomingContext(ctx); exists {
		if values := md.Get("x-forwarded-for"); len(values) > 0 {
			// X-Forwarded-For may contain multiple IPs separated by comma
			ips := strings.Split(values[0], ",")
			if len(ips) > 0 {
				return strings.TrimSpace(ips[0])
			}
		}

		// Try X-Real-IP
		if values := md.Get("x-real-ip"); len(values) > 0 {
			return values[0]
		}
	}

	return ""
}

// GetUserAgent extracts the User-Agent from gRPC metadata
func (u *utilities) GetUserAgent(ctx context.Context) string {
	if md, exists := metadata.FromIncomingContext(ctx); exists {
		if values := md.Get("user-agent"); len(values) > 0 {
			return values[0]
		}
		// Try grpc-user-agent as fallback
		if values := md.Get("grpc-user-agent"); len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
