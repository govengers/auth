package forwardauth

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	wideevent "github.com/govengers/wide-event-logger"

	"github.com/govengers/auth"
	"github.com/govengers/auth/ginadapter"
	"github.com/govengers/auth/prometheusadapter"
)

// maximumFieldBytes bounds each client-controlled field recordRequest adds to a wide event [LOG-009].
const maximumFieldBytes = 512

// ObserverOptions configure NewObserver.
type ObserverOptions struct {
	OutcomeCounter *prometheusadapter.OutcomeCounter // required: counts in forwardauth_auth_outcomes_total
}

// NewObserver returns the auth.Observer main passes to the provider, the Guard and the API keys: it
// records each outcome on the request's wide event and counts it in forwardauth_auth_outcomes_total.
func NewObserver(options *ObserverOptions) (auth.Observer, error) {
	if options == nil || options.OutcomeCounter == nil {
		return nil, errors.New("forwardauth observer: OutcomeCounter is required")
	}
	counter := options.OutcomeCounter
	return func(ctx context.Context, outcome auth.Outcome) {
		ginadapter.Observe(ctx, outcome)
		counter.Observe(ctx, outcome)
	}, nil
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

// recordRequest is the wide-event pre-enricher: it records the version and what Traefik asks to forward.
// The middleware records the request itself, cuts its client-controlled fields and redacts the query
// [LOG-009]. Only the path of X-Forwarded-Uri is recorded, never its query; each forward field is cut to
// maximumFieldBytes: 401s and unmatched paths are always kept.
func (s *Server) recordRequest(we *wideevent.Event, ginContext *gin.Context) {
	we.String("service.version", s.options.Version)
	if method := ginContext.GetHeader("X-Forwarded-Method"); method != "" {
		we.String("forward.method", truncated(method))
	}
	if host := ginContext.GetHeader("X-Forwarded-Host"); host != "" {
		we.String("forward.host", truncated(host))
	}
	if forwardedURI := ginContext.GetHeader("X-Forwarded-Uri"); forwardedURI != "" {
		forwardedPath, _, _ := strings.Cut(forwardedURI, "?")
		we.String("forward.path", truncated(forwardedPath))
	}
}

// truncated cuts value to at most maximumFieldBytes, at a character boundary.
func truncated(value string) string {
	if len(value) <= maximumFieldBytes {
		return value
	}
	cut := maximumFieldBytes
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut]
}
