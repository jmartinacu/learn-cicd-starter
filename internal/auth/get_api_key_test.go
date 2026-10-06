package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name       string
		headers    http.Header
		wantKey    string
		wantErr    error  // sentinel error expected, matched by identity
		wantErrMsg string // expected message for non-sentinel errors
	}{
		{
			name:    "valid API key",
			headers: http.Header{"Authorization": []string{"ApiKey valid_api_key"}},
			wantKey: "valid_api_key",
		},
		{
			name:    "empty header map",
			headers: http.Header{},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "empty authorization value",
			headers: http.Header{"Authorization": []string{""}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:    "unrelated header only",
			headers: http.Header{"Content-Type": []string{"application/json"}},
			wantErr: ErrNoAuthHeaderIncluded,
		},
		{
			name:       "wrong scheme",
			headers:    http.Header{"Authorization": []string{"Bearer some_token"}},
			wantErrMsg: "malformed authorization header",
		},
		{
			name:       "scheme without key",
			headers:    http.Header{"Authorization": []string{"ApiKey"}},
			wantErrMsg: "malformed authorization header",
		},
		{
			// Current behavior: only the second space-separated token is
			// returned; extra tokens are ignored.
			name:    "extra tokens after key",
			headers: http.Header{"Authorization": []string{"ApiKey key extra"}},
			wantKey: "key",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKey, err := GetAPIKey(tt.headers)

			if gotKey != tt.wantKey {
				t.Errorf("GetAPIKey() key = %q, want %q", gotKey, tt.wantKey)
			}

			switch {
			case tt.wantErr != nil:
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("GetAPIKey() error = %v, want %v", err, tt.wantErr)
				}
			case tt.wantErrMsg != "":
				if err == nil {
					t.Fatalf("GetAPIKey() error = nil, want %q", tt.wantErrMsg)
				}
				if err.Error() != tt.wantErrMsg {
					t.Errorf("GetAPIKey() error = %q, want %q", err.Error(), tt.wantErrMsg)
				}
			default:
				if err != nil {
					t.Errorf("GetAPIKey() error = %v, want nil", err)
				}
			}
		})
	}
}
