package forwardauth

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	wideevent "github.com/mxcd/go-wide-event-logger"

	"github.com/govengers/auth"
	"github.com/govengers/auth/ginadapter"
	"github.com/govengers/auth/prometheusadapter"
)

// maximumFieldBytes bounds each client-controlled field of a wide event [LOG-009].
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

// latestValues hands emitter a copy of every event with only the latest value of each field. The
// pre-enricher replaces request.query by setting it again; the JSON emitter prints the latest value,
// the dev emitter every value, the raw query included [LOG-009].
func latestValues(emitter wideevent.Emitter) wideevent.Emitter {
	return wideevent.EmitterFunc(func(we *wideevent.Event) {
		emitter.Emit(latestFields(we))
	})
}

// latestFields returns a new event with the latest value of each field of we, in the order of those values.
func latestFields(we *wideevent.Event) *wideevent.Event {
	fields := we.Fields()
	latest := make(map[string]int, len(fields))
	for index, field := range fields {
		latest[field.Key] = index
	}
	deduplicated := &wideevent.Event{}
	for index, field := range fields {
		if latest[field.Key] == index {
			deduplicated.Set(field.Key, field.Value)
		}
	}
	return deduplicated
}

// recordRequest is the wide-event pre-enricher: it replaces the query the middleware recorded verbatim
// (callbacks carry code and state) [LOG-009] and records the version and what Traefik asks to forward.
// Only the path of X-Forwarded-Uri is recorded, never its query. Every field a client controls is cut to
// maximumFieldBytes, also those the middleware recorded: 401s and unmatched paths are always kept.
func (s *Server) recordRequest(we *wideevent.Event, ginContext *gin.Context) {
	request := ginContext.Request
	we.Str("request.query", truncated(redactedQuery(request.URL.Query()))).
		Str("request.path", truncated(request.URL.Path)).
		Str("request.host", truncated(request.Host)).
		Str("request.user_agent", truncated(request.UserAgent())).
		Str("request.id", truncated(ginContext.GetHeader("X-Request-ID"))).
		Str("service.version", s.options.Version)
	if method := ginContext.GetHeader("X-Forwarded-Method"); method != "" {
		we.Str("forward.method", truncated(method))
	}
	if host := ginContext.GetHeader("X-Forwarded-Host"); host != "" {
		we.Str("forward.host", truncated(host))
	}
	if forwardedURI := ginContext.GetHeader("X-Forwarded-Uri"); forwardedURI != "" {
		forwardedPath, _, _ := strings.Cut(forwardedURI, "?")
		we.Str("forward.path", truncated(forwardedPath))
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

// redactedQuery keeps every parameter name and replaces every value with "redacted".
func redactedQuery(values url.Values) string {
	redacted := url.Values{}
	for name := range values {
		redacted.Set(name, "redacted")
	}
	return redacted.Encode()
}
