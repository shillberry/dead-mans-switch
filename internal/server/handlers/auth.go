package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/circa10a/dead-mans-switch/api"
)

// AuthConfigHandler serves the given auth configuration so the UI can discover OIDC settings.
func AuthConfigHandler(cfg api.AuthConfig) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(cfg)
	}
}

type tokenExchangeRequest struct {
	Code         string `json:"code"`
	CodeVerifier string `json:"codeVerifier"`
	RedirectURI  string `json:"redirectUri"`
}

// TokenExchangeHandler redeems the browser's authorization code without exposing the client secret.
func TokenExchangeHandler(tokenEndpoint, clientID, clientSecret string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		var exchange tokenExchangeRequest
		if err := decoder.Decode(&exchange); err != nil {
			http.Error(w, "invalid token exchange request", http.StatusBadRequest)
			return
		}
		if decoder.Decode(&struct{}{}) != io.EOF {
			http.Error(w, "invalid token exchange request", http.StatusBadRequest)
			return
		}
		if exchange.Code == "" || exchange.CodeVerifier == "" || exchange.RedirectURI == "" || clientID == "" {
			http.Error(w, "missing required token exchange fields", http.StatusBadRequest)
			return
		}
		if origin := r.Header.Get("Origin"); origin != "" {
			redirectURL, redirectErr := url.Parse(exchange.RedirectURI)
			originURL, originErr := url.Parse(origin)
			if redirectErr != nil || originErr != nil || redirectURL.Scheme != originURL.Scheme || redirectURL.Host != originURL.Host {
				http.Error(w, "redirect URI must match request origin", http.StatusBadRequest)
				return
			}
		}

		form := url.Values{
			"grant_type":    {"authorization_code"},
			"code":          {exchange.Code},
			"redirect_uri":  {exchange.RedirectURI},
			"client_id":     {clientID},
			"code_verifier": {exchange.CodeVerifier},
		}
		if clientSecret != "" {
			form.Set("client_secret", clientSecret)
		}

		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
		if err != nil {
			http.Error(w, "failed to create token request", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		client := &http.Client{
			Timeout: 10 * time.Second,
			CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "token provider request failed", http.StatusBadGateway)
			return
		}
		defer func() { _ = resp.Body.Close() }()

		body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil {
			http.Error(w, "failed to read token provider response", http.StatusBadGateway)
			return
		}
		if len(body) > 1<<20 {
			http.Error(w, "token provider response is too large", http.StatusBadGateway)
			return
		}
		if !json.Valid(bytes.TrimSpace(body)) {
			http.Error(w, fmt.Sprintf("token provider returned an invalid response (HTTP %d)", resp.StatusCode), http.StatusBadGateway)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
	}
}
