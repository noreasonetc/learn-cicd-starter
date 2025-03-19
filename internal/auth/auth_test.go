package auth

import (
	"errors"
	"net/http"
	"testing"
)

// TestGetAPIKey validates different scenarios for extracting the API key from headers
func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name        string
		headers     http.Header
		expectedKey string
		expectErr   error
	}{
		{
			name:        "Valid API Key",
			headers:     http.Header{"Authorization": []string{"ApiKey my-secret-key"}},
			expectedKey: "my-secret-key",
			expectErr:   nil,
		},
		{
			name:        "Missing Authorization Header",
			headers:     http.Header{},
			expectedKey: "",
			expectErr:   ErrNoAuthHeaderIncluded,
		},
		{
			name:        "Malformed Authorization Header - No Key",
			headers:     http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey: "",
			expectErr:   errors.New("malformed authorization header"),
		},
		{
			name:        "Malformed Authorization Header - Wrong Prefix",
			headers:     http.Header{"Authorization": []string{"Bearer my-secret-key"}},
			expectedKey: "",
			expectErr:   errors.New("malformed authorization header"),
		},
		{
			name:        "Empty Authorization Header",
			headers:     http.Header{"Authorization": []string{""}},
			expectedKey: "",
			expectErr:   ErrNoAuthHeaderIncluded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			apiKey, err := GetAPIKey(tt.headers)

			// Validate API key extraction
			if apiKey != tt.expectedKey {
				t.Errorf("expected API key: %s, got: %s", tt.expectedKey, apiKey)
			}

			// Validate error correctness
			if err != nil && tt.expectErr != nil {
				if err.Error() != tt.expectErr.Error() {
					t.Errorf("expected error: %v, got: %v", tt.expectErr, err)
				}
			} else if err != tt.expectErr {
				t.Errorf("expected error: %v, got: %v", tt.expectErr, err)
			}
		})
	}
}

