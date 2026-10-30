package ginadapter_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/gin-gonic/gin"
	wideevent "github.com/govengers/wide-event-logger"
	wideeventgin "github.com/govengers/wide-event-logger/ginadapter"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/ginadapter"
)

func Example() {
	// requireAPI stands in for session.Guard.RequireAPI: it authenticates the request from its session.
	requireAPI := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			identity := &auth.Identity{Provider: "password", Subject: request.Header.Get("X-Example-User"), Active: true}
			if identity.Subject == "admin-1" {
				identity.Roles = []string{auth.RoleAdmin}
			}
			next.ServeHTTP(writer, request.WithContext(auth.WithIdentity(request.Context(), identity)))
		})
	}

	wideEvents, err := wideeventgin.NewMiddleware(&wideeventgin.Options{Emitter: wideevent.EmitterFunc(func(*wideevent.Event) {})})
	if err != nil {
		fmt.Println(err)
		return
	}
	engine := gin.New()
	engine.Use(wideEvents)
	api := engine.Group("/api", ginadapter.Middleware(requireAPI))
	api.GET("/reports", ginadapter.Require(authorization.IsAdmin()), func(ginContext *gin.Context) {
		ginContext.String(http.StatusOK, "reports")
	})

	for _, subject := range []string{"admin-1", "user-7"} {
		request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/reports", nil)
		request.Header.Set("X-Example-User", subject)
		recorder := httptest.NewRecorder()
		engine.ServeHTTP(recorder, request)
		fmt.Println(subject, recorder.Code)
	}
	// Output:
	// admin-1 200
	// user-7 403
}
