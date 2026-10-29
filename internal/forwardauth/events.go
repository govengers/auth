package forwardauth

import (
	"context"
	"net/http"
	"net/url"
	"strings"

	"github.com/gin-gonic/gin"
	wideevent "github.com/mxcd/go-wide-event-logger"

	"github.com/govengers/auth"
	"github.com/govengers/auth/ginadapter"
	"github.com/govengers/auth/prometheusadapter"
)

// NewObserver returns the auth.Observer main passes to the provider, the Guard and the API keys: it
// records each outcome on the request's wide event and counts it in forwardauth_auth_outcomes_total.
func NewObserver(counter *prometheusadapter.OutcomeCounter) auth.Observer {
	return func(ctx context.Context, outcome auth.Outcome) {
		ginadapter.Observe(ctx, outcome)
		counter.Observe(ctx, outcome)
	}
}

// sampler keeps every failure, 5xx, 401, 403 and degraded event and every rateth of the rest [LOG-010].
func sampler(rate int) wideevent.Sampler {
	keepDegraded := wideevent.SamplerFunc(func(candidate *wideevent.Event) bool {
		degraded, _ := candidate.FieldsMap()["degraded"].(bool)
		return degraded
	})
	return wideevent.CompositeSampler(
		wideevent.AlwaysOnError(),
		wideevent.AlwaysOnStatus(http.StatusUnauthorized, http.StatusForbidden),
		keepDegraded,
		wideevent.Rate(rate),
	)
}

// recordRequest is the wide-event pre-enricher: it replaces the query the middleware recorded verbatim
// (callbacks carry code and state) [LOG-009] and records the version and what Traefik asks to forward.
// Only the path of X-Forwarded-Uri is recorded, never its query.
func (s *Server) recordRequest(we *wideevent.Event, ginContext *gin.Context) {
	we.Str("request.query", redactedQuery(ginContext.Request.URL.Query())).
		Str("service.version", s.options.Version)
	if method := ginContext.GetHeader("X-Forwarded-Method"); method != "" {
		we.Str("forward.method", method)
	}
	if host := ginContext.GetHeader("X-Forwarded-Host"); host != "" {
		we.Str("forward.host", host)
	}
	if forwardedURI := ginContext.GetHeader("X-Forwarded-Uri"); forwardedURI != "" {
		forwardedPath, _, _ := strings.Cut(forwardedURI, "?")
		we.Str("forward.path", forwardedPath)
	}
}

// redactedQuery keeps every parameter name and replaces every value with "redacted".
func redactedQuery(values url.Values) string {
	redacted := url.Values{}
	for name := range values {
		redacted.Set(name, "redacted")
	}
	return redacted.Encode()
}
