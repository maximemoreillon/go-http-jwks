package auth

import (
	"context"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

var cache *jwk.Cache
var cacheInit sync.Once

// getKeyset retrieves the JWKS keyset, initializing the cache if necessary.
func getKeyset(certsUrl string) (jwk.Set, error) {
	var keyset jwk.Set
	var err error

	cacheInit.Do(func() {
		bgCtx := context.Background()
		cache, err = jwk.NewCache(bgCtx, httprc.NewClient())
		if err != nil {
			log.Printf("[ERROR] Failed to create JWKS cache: %v", err)
			return
		}

		err = cache.Register(bgCtx, certsUrl,
			jwk.WithMaxInterval(24*time.Hour),
			jwk.WithMinInterval(15*time.Minute),
		)
		if err != nil {
			log.Printf("[ERROR] Failed to register JWKS URL %s: %v", certsUrl, err)
			return
		}

		_, err = cache.CachedSet(certsUrl)
		if err != nil {
			log.Printf("[ERROR] Failed to pre-fetch JWKS from %s: %v", certsUrl, err)
			return
		}
	})

	if cache == nil {
		log.Printf("[ERROR] Cache is nil, initialization failed")
		return nil, err
	}

	keyset, err = cache.CachedSet(certsUrl)
	if err != nil {
		log.Printf("[ERROR] Failed to get cached JWKS for %s: %v", certsUrl, err)
	}

	return keyset, err
}

// Middleware creates an authentication middleware for OIDC token validation
func Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Get JWKS URL from environment variable
		certsUrl, hasEnv := os.LookupEnv("JWKS_URI")
		if !hasEnv {
			log.Printf("[ERROR] JWKS_URI not set")
			http.Error(w, `{"message": "JWKS_URI not set", "code": "ENV_MISSING"}`, http.StatusInternalServerError)
			return
		}

		// Get the cached keyset
		keyset, err := getKeyset(certsUrl)
		if err != nil {
			log.Printf("[ERROR] Failed to get cached JWKS: %v", err)
			http.Error(w, `{"message": "Authentication service unavailable", "code": "JWKS_CACHE_FAILED"}`, http.StatusInternalServerError)
			return
		}

		// Check for Authorization header
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			log.Printf("[WARNING] Authorization header not set")
			http.Error(w, `{"message": "Authorization header not set", "code": "AUTH_HEADER_MISSING"}`, http.StatusForbidden)
			return
		}

		// Extract Bearer token
		parts := strings.Split(authHeader, "Bearer ")
		if len(parts) != 2 {
			log.Printf("[WARNING] Invalid Authorization header format: %s", authHeader)
			http.Error(w, `{"message": "Invalid Authorization header format", "code": "AUTH_HEADER_INVALID"}`, http.StatusUnauthorized)
			return
		}

		jwtToken := parts[1]

		// Parse and verify token using the cached keyset
		_, err = jwt.Parse([]byte(jwtToken), jwt.WithKeySet(keyset))
		if err != nil {
			log.Printf("[WARNING] Token verification failed: %v", err)
			http.Error(w, `{"message": "Invalid token", "code": "TOKEN_INVALID"}`, http.StatusUnauthorized)
			return
		}

		// Token is valid, proceed to next handler
		next.ServeHTTP(w, r)
	})
}
