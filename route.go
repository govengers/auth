package auth

import "net/http"

// Route is one endpoint a provider serves. Path is absolute from the server root and includes the provider prefix.
type Route struct {
	Method  string
	Path    string
	Handler http.Handler
}

// RegisterRoutes registers each route on serveMux as the Go 1.22 pattern "<Method> <Path>". Like
// http.ServeMux.Handle it panics on a pattern that conflicts with one already registered, which is a
// wiring mistake at startup.
func RegisterRoutes(serveMux *http.ServeMux, routes []Route) {
	for _, route := range routes {
		serveMux.Handle(route.Method+" "+route.Path, route.Handler)
	}
}
