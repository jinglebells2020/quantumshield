package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Role string

const (
	RoleAdmin     Role = "admin"
	RoleSecurity  Role = "security"
	RoleDeveloper Role = "developer"
	RoleViewer    Role = "viewer"
	RoleCI        Role = "ci"
)

// Permissions per role
var RolePermissions = map[Role][]string{
	RoleAdmin:     {"scan:read", "scan:write", "finding:read", "finding:write", "finding:triage", "org:manage", "api_key:manage", "report:read", "report:write"},
	RoleSecurity:  {"scan:read", "scan:write", "finding:read", "finding:write", "finding:triage", "report:read", "report:write"},
	RoleDeveloper: {"scan:read", "finding:read", "finding:write"},
	RoleViewer:    {"scan:read", "finding:read", "report:read"},
	RoleCI:        {"scan:read", "scan:write"},
}

// APIKey represents a stored API key.
type APIKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	KeyHash   string    `json:"-"`
	Prefix    string    `json:"prefix"`
	Role      Role      `json:"role"`
	OrgID     string    `json:"org_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
	LastUsed  time.Time `json:"last_used,omitempty"`
}

// AuthManager handles API key creation and validation.
type AuthManager struct {
	keys map[string]*APIKey // keyHash -> key
	mu   sync.RWMutex
}

// NewAuthManager creates an auth manager.
func NewAuthManager() *AuthManager {
	return &AuthManager{keys: make(map[string]*APIKey)}
}

// CreateAPIKey generates a new API key and returns the plaintext key (only shown once).
func (am *AuthManager) CreateAPIKey(name, orgID string, role Role) (plaintext string, key *APIKey, err error) {
	// Generate 32 random bytes
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generating key: %w", err)
	}
	plaintext = "qs_" + hex.EncodeToString(raw)
	hash := hashKey(plaintext)
	prefix := plaintext[:10] + "..."

	key = &APIKey{
		ID:        fmt.Sprintf("key_%s", hex.EncodeToString(raw[:8])),
		Name:      name,
		KeyHash:   hash,
		Prefix:    prefix,
		Role:      role,
		OrgID:     orgID,
		CreatedAt: time.Now(),
	}

	am.mu.Lock()
	am.keys[hash] = key
	am.mu.Unlock()

	return plaintext, key, nil
}

// ValidateKey checks an API key and returns the associated key info.
func (am *AuthManager) ValidateKey(plaintext string) (*APIKey, error) {
	hash := hashKey(plaintext)
	am.mu.RLock()
	key, ok := am.keys[hash]
	am.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("invalid API key")
	}
	if !key.ExpiresAt.IsZero() && time.Now().After(key.ExpiresAt) {
		return nil, fmt.Errorf("API key expired")
	}
	am.mu.Lock()
	key.LastUsed = time.Now()
	am.mu.Unlock()
	return key, nil
}

// HasPermission checks if a role has a specific permission.
func HasPermission(role Role, permission string) bool {
	perms, ok := RolePermissions[role]
	if !ok {
		return false
	}
	for _, p := range perms {
		if p == permission {
			return true
		}
	}
	return false
}

// Middleware returns an HTTP middleware that validates API keys.
func (am *AuthManager) Middleware(requiredPermission string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Extract key from Authorization header
			auth := r.Header.Get("Authorization")
			if auth == "" {
				// Allow unauthenticated access for health/root endpoints
				next.ServeHTTP(w, r)
				return
			}

			token := strings.TrimPrefix(auth, "Bearer ")
			key, err := am.ValidateKey(token)
			if err != nil {
				http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
				return
			}

			if requiredPermission != "" && !HasPermission(key.Role, requiredPermission) {
				http.Error(w, `{"error":"forbidden"}`, http.StatusForbidden)
				return
			}

			// Add key info to request context (simplified -- use context in production)
			r.Header.Set("X-QS-OrgID", key.OrgID)
			r.Header.Set("X-QS-Role", string(key.Role))
			r.Header.Set("X-QS-KeyID", key.ID)

			next.ServeHTTP(w, r)
		})
	}
}

// ListKeys returns all API keys for an org (without hashes).
func (am *AuthManager) ListKeys(orgID string) []APIKey {
	am.mu.RLock()
	defer am.mu.RUnlock()
	var keys []APIKey
	for _, k := range am.keys {
		if k.OrgID == orgID {
			keys = append(keys, *k)
		}
	}
	return keys
}

// RevokeKey removes an API key.
func (am *AuthManager) RevokeKey(keyID string) bool {
	am.mu.Lock()
	defer am.mu.Unlock()
	for hash, k := range am.keys {
		if k.ID == keyID {
			delete(am.keys, hash)
			return true
		}
	}
	return false
}

func hashKey(plaintext string) string {
	h := sha256.Sum256([]byte(plaintext))
	return hex.EncodeToString(h[:])
}
