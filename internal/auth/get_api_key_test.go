package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name      string
		authValue string
		wantKey   string
		wantErr   error
	}{
		{
			name:    "missing authorization header",
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:      "malformed authorization header",
			authValue: "Bearer abc123",
			wantErr:   errors.New("malformed authorization header"),
		},
		{
			name:      "malformed authorization header",
			authValue: "Bearer token abc123",
			wantErr:   errors.New("malformed authorization header"),
		},
		{
			name:      "valid api key",
			authValue: "ApiKey abc123",
			wantKey:   "abc123",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			headers := http.Header{}
			if tc.authValue != "" {
				headers.Set("Authorization", tc.authValue)
			}

			gotKey, gotErr := GetAPIKey(headers)
			if gotKey != tc.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tc.wantKey)
			}
			if (gotErr == nil) != (tc.wantErr == nil) {
				t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tc.wantErr)
			}
			if gotErr != nil && gotErr.Error() != tc.wantErr.Error() {
				t.Errorf("GetAPIKey() error = %v, want %v", gotErr, tc.wantErr)
			}
		})
	}
}
