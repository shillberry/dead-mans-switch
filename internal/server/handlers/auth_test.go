package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/circa10a/dead-mans-switch/api"
)

func TestAuthGetConfigHandleFunc(t *testing.T) {
	audience := "my-client-id"
	issuer := "http://localhost:9000/application/o/dead-mans-switch/"

	tests := []struct {
		name             string
		cfg              api.AuthConfig
		expectedAudience string
		expectedEnabled  bool
		expectedIssuer   string
	}{
		{
			name: "auth disabled",
			cfg: api.AuthConfig{
				Enabled: false,
			},
			expectedEnabled: false,
		},
		{
			name: "auth enabled with issuer and audience",
			cfg: api.AuthConfig{
				Audience:  &audience,
				Enabled:   true,
				IssuerUrl: &issuer,
			},
			expectedAudience: "my-client-id",
			expectedEnabled:  true,
			expectedIssuer:   "http://localhost:9000/application/o/dead-mans-switch/",
		},
		{
			name: "auth enabled without audience",
			cfg: api.AuthConfig{
				Enabled:   true,
				IssuerUrl: &issuer,
			},
			expectedEnabled: true,
			expectedIssuer:  "http://localhost:9000/application/o/dead-mans-switch/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/config", nil)
			rec := httptest.NewRecorder()

			handler := AuthConfigHandler(tt.cfg)
			handler(rec, req)

			if rec.Code != http.StatusOK {
				t.Errorf("expected status 200, got %d", rec.Code)
			}

			contentType := rec.Header().Get("Content-Type")
			if contentType != "application/json" {
				t.Errorf("expected Content-Type application/json, got %s", contentType)
			}

			var resp api.AuthConfig
			err := json.NewDecoder(rec.Body).Decode(&resp)
			if err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			if resp.Enabled != tt.expectedEnabled {
				t.Errorf("expected enabled=%v, got %v", tt.expectedEnabled, resp.Enabled)
			}

			issuerUrl := ""
			if resp.IssuerUrl != nil {
				issuerUrl = *resp.IssuerUrl
			}
			if issuerUrl != tt.expectedIssuer {
				t.Errorf("expected issuerUrl=%q, got %q", tt.expectedIssuer, issuerUrl)
			}

			audience := ""
			if resp.Audience != nil {
				audience = *resp.Audience
			}
			if audience != tt.expectedAudience {
				t.Errorf("expected audience=%q, got %q", tt.expectedAudience, audience)
			}
		})
	}
}

func TestTokenExchangeHandlerKeepsClientSecretServerSide(t *testing.T) {
	const clientSecret = "server-only-secret"
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if got := r.Header.Get("Content-Type"); got != "application/x-www-form-urlencoded" {
			t.Errorf("expected form content type, got %q", got)
		}
		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse provider request: %v", err)
			return
		}
		want := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {"authorization-code"},
			"redirect_uri":  {"https://switch.example.com/"},
			"client_id":     {"google-client-id"},
			"client_secret": {clientSecret},
			"code_verifier": {"pkce-verifier"},
		}
		if r.Form.Encode() != want.Encode() {
			t.Errorf("unexpected provider form: got %v, want %v", r.Form, want)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-token","id_token":"id-token"}`))
	}))
	defer provider.Close()

	handler := TokenExchangeHandler(provider.URL, "google-client-id", clientSecret)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(`{"code":"authorization-code","codeVerifier":"pkce-verifier","redirectUri":"https://switch.example.com/"}`))
	request.Header.Set("Origin", "https://switch.example.com")
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), clientSecret) {
		t.Error("response exposed the OAuth client secret")
	}
	if !strings.Contains(recorder.Body.String(), `"id_token":"id-token"`) {
		t.Errorf("expected token provider response to be returned, got %q", recorder.Body.String())
	}
}

func TestTokenExchangeHandlerRejectsCrossOriginRedirect(t *testing.T) {
	handler := TokenExchangeHandler("https://oauth.example.com/token", "client-id", "client-secret")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(`{"code":"code","codeVerifier":"verifier","redirectUri":"https://attacker.example/"}`))
	request.Header.Set("Origin", "https://switch.example.com")
	recorder := httptest.NewRecorder()
	handler(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Errorf("expected status 400 for cross-origin redirect, got %d", recorder.Code)
	}
}

func TestTokenExchangeHandlerSupportsPublicClients(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Errorf("failed to parse provider request: %v", err)
			return
		}
		if r.Form.Has("client_secret") {
			t.Error("public-client exchange unexpectedly included client_secret")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"access_token":"access-token"}`))
	}))
	defer provider.Close()

	handler := TokenExchangeHandler(provider.URL, "public-client-id", "")
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/token", strings.NewReader(`{"code":"code","codeVerifier":"verifier","redirectUri":"http://switch.example.com/"}`))
	recorder := httptest.NewRecorder()
	handler(recorder, request)
	if recorder.Code != http.StatusOK {
		t.Errorf("expected status 200 for public client, got %d: %s", recorder.Code, recorder.Body.String())
	}
}
