package fakeprovider

import (
	"crypto/rand"
	"net/http"
	"net/url"
	"strings"
)

// keycloakClientUUID is the internal ID of the one client the fake realm knows: OIDCOptions.ClientID.
const keycloakClientUUID = "6f1d2c3a-9a51-4c3a-8e4c-1a773f2d8e4c"

type keycloakRole struct {
	Name string `json:"name"`
}

// registerKeycloakRoutes serves the Keycloak token endpoint (client credentials and password grant) at
// /realms/{realm}/protocol/openid-connect/token for KeycloakAuthenticationRealm, and the five Admin API
// GETs the keycloak package calls for KeycloakRealm, answering for User. Admin GETs need a token of that
// endpoint; an unknown user, client or realm is a 404, as in Keycloak.
func (h *OIDCHandler) registerKeycloakRoutes(serveMux *http.ServeMux) {
	serveMux.HandleFunc("POST /realms/{realm}/protocol/openid-connect/token", h.keycloakToken)
	serveMux.HandleFunc("GET /admin/realms/{realm}/users/{user}/role-mappings/realm/composite", h.requireAdmin(h.keycloakRealmRoles))
	serveMux.HandleFunc("GET /admin/realms/{realm}/clients", h.requireAdmin(h.keycloakClients))
	serveMux.HandleFunc("GET /admin/realms/{realm}/users/{user}/role-mappings/clients/{client}/composite", h.requireAdmin(h.keycloakClientRoles))
	serveMux.HandleFunc("GET /admin/realms/{realm}/users/{user}/groups", h.requireAdmin(h.keycloakGroups))
	serveMux.HandleFunc("GET /admin/realms/{realm}/users/{user}", h.requireAdmin(h.keycloakUser))
}

// KeycloakTokenRequests returns how many requests reached the Keycloak token endpoint.
func (h *OIDCHandler) KeycloakTokenRequests() int {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.keycloakTokenRequests
}

// KeycloakClientLookups returns how many client lookups (GET /clients?clientId=) the Admin API answered.
func (h *OIDCHandler) KeycloakClientLookups() int {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	return h.keycloakClientLookups
}

// RevokeKeycloakTokens invalidates every admin token issued so far, as Keycloak does before their expiry
// (key rotation, a logout of the service account): the Admin API answers 401 to them.
func (h *OIDCHandler) RevokeKeycloakTokens() {
	h.mutex.Lock()
	defer h.mutex.Unlock()
	clear(h.adminTokens)
}

func (h *OIDCHandler) keycloakToken(writer http.ResponseWriter, request *http.Request) {
	h.mutex.Lock()
	h.keycloakTokenRequests++
	h.mutex.Unlock()
	if request.PathValue("realm") != h.options.KeycloakAuthenticationRealm {
		http.NotFound(writer, request)
		return
	}
	form, err := readForm(writer, request)
	if err != nil {
		oauthError(writer, http.StatusBadRequest, invalidRequest)
		return
	}
	if !h.adminGrantValid(request, form) {
		oauthError(writer, http.StatusUnauthorized, invalidGrant)
		return
	}
	token := rand.Text()
	h.mutex.Lock()
	h.adminTokens[token] = true
	h.mutex.Unlock()
	writeJSON(writer, http.StatusOK, map[string]any{"access_token": token, "token_type": "Bearer", "expires_in": int(tokenLifetime.Seconds())})
}

func (h *OIDCHandler) adminGrantValid(request *http.Request, form url.Values) bool {
	switch form.Get("grant_type") {
	case "client_credentials":
		clientID, clientSecret := clientCredentials(request, form)
		return matches(clientID, h.options.KeycloakClientID) && matches(clientSecret, h.options.KeycloakClientSecret)
	case "password":
		return matches(form.Get("username"), h.options.KeycloakUsername) && matches(form.Get("password"), h.options.KeycloakPassword)
	default:
		return false
	}
}

// requireAdmin answers 401 without an admin token of this fake and 404 for another realm or user.
func (h *OIDCHandler) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(writer http.ResponseWriter, request *http.Request) {
		token, _ := strings.CutPrefix(request.Header.Get("Authorization"), "Bearer ")
		h.mutex.Lock()
		valid := h.adminTokens[token]
		h.mutex.Unlock()
		if !valid {
			writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "HTTP 401 Unauthorized"})
			return
		}
		user := request.PathValue("user")
		if request.PathValue("realm") != h.options.KeycloakRealm || (user != "" && user != h.options.User.Subject) {
			http.NotFound(writer, request)
			return
		}
		next(writer, request)
	}
}

func (h *OIDCHandler) keycloakRealmRoles(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, roles(h.options.User.RealmRoles))
}

func (h *OIDCHandler) keycloakClients(writer http.ResponseWriter, request *http.Request) {
	h.mutex.Lock()
	h.keycloakClientLookups++
	h.mutex.Unlock()
	clients := []map[string]string{}
	if request.URL.Query().Get("clientId") == h.options.ClientID {
		clients = append(clients, map[string]string{"id": keycloakClientUUID, "clientId": h.options.ClientID})
	}
	writeJSON(writer, http.StatusOK, clients)
}

func (h *OIDCHandler) keycloakClientRoles(writer http.ResponseWriter, request *http.Request) {
	if request.PathValue("client") != keycloakClientUUID {
		http.NotFound(writer, request)
		return
	}
	writeJSON(writer, http.StatusOK, roles(h.options.User.ClientRoles))
}

func (h *OIDCHandler) keycloakGroups(writer http.ResponseWriter, _ *http.Request) {
	groups := make([]map[string]string, 0, len(h.options.User.Groups))
	for _, path := range h.options.User.Groups {
		groups = append(groups, map[string]string{"id": rand.Text(), "name": path[strings.LastIndex(path, "/")+1:], "path": path})
	}
	writeJSON(writer, http.StatusOK, groups)
}

func (h *OIDCHandler) keycloakUser(writer http.ResponseWriter, _ *http.Request) {
	user := h.options.User
	writeJSON(writer, http.StatusOK, map[string]any{"id": user.Subject, "username": user.PreferredUsername, "attributes": user.Attributes})
}

func roles(names []string) []keycloakRole {
	result := make([]keycloakRole, 0, len(names))
	for _, name := range names {
		result = append(result, keycloakRole{Name: name})
	}
	return result
}
