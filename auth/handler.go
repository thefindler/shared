import (
	"context"
	"encoding/json"
	"net/http"
)

// AuthHandler wraps the AuthService to provide HTTP handlers.
type AuthHandler struct {
	service *AuthService
}

// NewAuthHandler creates a new handler for auth endpoints.
func NewAuthHandler(service *AuthService) *AuthHandler {
	return &AuthHandler{service: service}
}

func (h *AuthHandler) LoginHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	access, refresh, err := h.service.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		authErr, ok := err.(*AuthError)
		if ok {
			http.Error(w, authErr.Message, authErr.Code)
		} else {
			http.Error(w, "Login failed", http.StatusUnauthorized)
		}
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token":  access,
		"refresh_token": refresh,
	})
}

func (h *AuthHandler) RefreshHandler(w http.ResponseWriter, r *http.Request) {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	token, err := h.service.Refresh(r.Context(), req.RefreshToken)
	if err != nil {
		authErr, ok := err.(*AuthError)
		if ok {
			http.Error(w, authErr.Message, authErr.Code)
		} else {
			http.Error(w, "Failed to refresh token", http.StatusUnauthorized)
		}
		return
	}

	json.NewEncoder(w).Encode(map[string]string{
		"access_token": token,
	})
}

// CreateUserHandler handles new user creation. This is a protected endpoint.
func (h *AuthHandler) CreateUserHandler(w http.ResponseWriter, r *http.Request) {
	// Authorization is now handled by the middleware that wraps this handler in the router.
	// No explicit authorization check is needed here.

	var req struct {
		Username    string   `json:"username"`
		Password    string   `json:"password"`
		Role        string   `json:"role"`
		UserType    string   `json:"user_type"`
		OrgID       *string  `json:"organisation_id"`
		Permissions []string `json:"permissions"`
	}

	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	err := h.service.CreateUser(r.Context(), req.Username, req.Password, req.Role, req.UserType, req.OrgID, req.Permissions)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
}