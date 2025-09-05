package auth

import (
    "net/http"
    "net/http/httptest"
    "testing"
	"strings"
)

func TestGetAPIKey(t *testing.T) {
    tests := []struct {
        name          string
        headerValue   string
        expectedKey   string
        expectError   bool
        errorContains string
    }{
        {
            name:        "Valid API Key",
            headerValue: "ApiKey xyz123",
            expectedKey: "xyz123",
            expectError: false,
        },
        {
            name:          "Invalid Prefix",
            headerValue:   "Bearer abc456",
            expectedKey:   "",
            expectError:   true,
            errorContains: "malformed authorization header",
        },
        {
            name:          "Missing Authorization Header",
            headerValue:   "",
            expectedKey:   "",
            expectError:   true,
            errorContains: "no authorization header included",
        },
        {
            name:          "Missing ApiKey Prefix",
            headerValue:   "xyz123",
            expectedKey:   "",
            expectError:   true,
            errorContains: "malformed authorization header",
        },
        {
            name:          "ApiKey with Empty Token",
            headerValue:   "ApiKey ",
            expectedKey:   "",
            expectError:   true,
            errorContains: "malformed authorization header",
        },
    }

    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            // Create a request with the test header
            req := httptest.NewRequest(http.MethodGet, "/", nil)
            if tt.headerValue != "" {
                req.Header.Set("Authorization", tt.headerValue)
            }

            // Call the function being tested
            key, err := GetAPIKey(req.Header)

            // Check error expectations
            if tt.expectError {
                if err == nil {
                    t.Errorf("expected error but got nil")
                    return
                }
                if tt.errorContains != "" && !contains(err.Error(), tt.errorContains) {
                    t.Errorf("expected error to contain %q but got %q", tt.errorContains, err.Error())
                }
            } else {
                if err != nil {
                    t.Errorf("unexpected error: %v", err)
                    return
                }
            }

            // Check key expectations
            if key != tt.expectedKey {
                t.Errorf("expected key %q but got %q", tt.expectedKey, key)
            }
        })
    }
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
    return s != "" && substr != "" && strings.Contains(s, substr)
}

func TestGetAPIKeyWithDifferentHeader(t *testing.T) {
    // Create a request with X-API-Key header instead of Authorization
    req := httptest.NewRequest(http.MethodGet, "/", nil)
    req.Header.Set("X-API-Key", "test-key")
    
    // The function should look for Authorization header, so this should result in an error
    key, err := GetAPIKey(req.Header)
    
    if err == nil {
        t.Errorf("expected error when using different header, but got nil")
    }
    
    if key != "" {
        t.Errorf("expected empty key but got %q", key)
    }
}