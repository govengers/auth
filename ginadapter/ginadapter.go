// Package ginadapter integrates the module with gin and the wide-event logger: it runs the net/http
// middleware of the providers in a gin chain, registers their routes on a gin router, gates routes
// with authorization checks, and records authentication outcomes on the request's wide event.
//
// It is the only package of the library that imports gin and wide-event-logger. It records on the
// wide event the wide-event middleware (wide-event-logger's ginadapter.NewMiddleware) put into the request
// context and never emits one of its own; it records IDs and decisions, never usernames, emails, names,
// tokens or codes. That middleware redacts every query value itself, so the code and state of OAuth
// callbacks stay out of your logs. Everything in it is safe for concurrent use.
package ginadapter

import (
	"context"
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	wideevent "github.com/govengers/wide-event-logger"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
)

// Middleware runs net/http middleware in a gin chain: when it calls its next handler, ginContext.Request
// becomes the (possibly enriched) request and the rest of the chain runs inside it; otherwise the chain is aborted.
// Like a net/http chain it wraps once, here, so state the middleware keeps across requests survives. Each
// request finds its gin chain through its context: a middleware that passes on a request whose context does
// not derive from the one it got is answered 500.
// Gin handlers keep writing to ginContext.Writer, so a writer the middleware wraps for its next handler is not seen.
func Middleware(middleware func(http.Handler) http.Handler) gin.HandlerFunc {
	handler := middleware(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		chain, found := request.Context().Value(chainKey{}).(*ginChain)
		if !found {
			auth.WriteError(writer, errChainLost)
			return
		}
		chain.passed = true
		chain.ginContext.Request = request
		chain.ginContext.Next()
	}))
	return func(ginContext *gin.Context) {
		chain := &ginChain{ginContext: ginContext}
		ctx := context.WithValue(ginContext.Request.Context(), chainKey{}, chain)
		handler.ServeHTTP(ginContext.Writer, ginContext.Request.WithContext(ctx))
		if !chain.passed {
			ginContext.Abort()
		}
	}
}

// chainKey is the request context key of the request's ginChain.
type chainKey struct{}

// ginChain is the rest of one request's gin chain, which Middleware's next handler runs.
type ginChain struct {
	ginContext *gin.Context
	passed     bool
}

// errChainLost is the internal failure of a middleware that passed on a request without its gin chain.
var errChainLost = errors.New("ginadapter: the middleware passed on a request without its gin chain")

// RegisterRoutes registers each route with router.Handle(route.Method, route.Path, gin.WrapH(route.Handler)),
// so gin route templates (and therefore metric labels) are the provider paths. Register on the engine root.
// Like gin it panics on a path that conflicts with one already registered, which is a wiring mistake at startup.
func RegisterRoutes(router gin.IRoutes, routes []auth.Route) {
	for _, route := range routes {
		router.Handle(route.Method, route.Path, gin.WrapH(route.Handler))
	}
}

// Observe is an auth.Observer that records the outcome on the request's wide event: auth.provider,
// auth.action, auth.result, the client code, reason and error of Err, degraded for a success with Err,
// the subject and user ID of the identity (the impersonator's subject and the impersonated subject while
// impersonating), and the request outcome when the outcome decided it.
// A session.Guard reports a refresh on the same event before the request's authenticate outcome, so a
// refresh outcome goes under auth.refresh.* instead, without the user ID: no key is set twice. For the same
// reason a session.Impersonator's outcome, which follows the Guard's, goes under auth.impersonation.*.
// Without a wide event in ctx it records nothing.
func Observe(ctx context.Context, outcome auth.Outcome) {
	we := wideevent.FromContext(ctx)
	prefix := requestPrefix
	if outcome.Action == auth.ActionRefresh {
		prefix = refreshPrefix
	}
	if outcome.Action == auth.ActionImpersonationStart || outcome.Action == auth.ActionImpersonationStop {
		prefix = impersonationPrefix
	}
	recordDecision(we, prefix, outcome)
	recordOutcomeError(we, prefix, outcome)
	recordIdentity(we, prefix, outcome.Identity)
	recordRequestOutcome(we, outcome)
}

// RedactQuery does nothing.
//
// Deprecated: the wide-event-logger v1 middleware (ginadapter.NewMiddleware) redacts request.query itself:
// every value becomes "redacted" unless its parameter is in Options.QueryAllowlist. Drop RedactQuery from
// your pre-enricher; it stays so enrichers that mount or call it keep compiling once they move to
// wide-event-logger v1.
func RedactQuery(we *wideevent.Event, ginContext *gin.Context) {}

// The key prefixes of an outcome's fields.
const (
	requestPrefix       = "auth."
	refreshPrefix       = "auth.refresh."
	impersonationPrefix = "auth.impersonation."
)

// errNilCheck is the internal failure a Require without a check answers with.
var errNilCheck = errors.New("authorization check is nil")

// Require runs check against the request context: allowed continues; refused aborts with auth.ResponseFor
// (401/403/500) and records authorization.denied / authorization.reason / authorization.error and we.Failure(err).
// A nil check is a wiring mistake: every request is answered 500.
func Require(check authorization.Check) gin.HandlerFunc {
	if check == nil {
		check = func(context.Context) error { return errNilCheck }
	}
	return func(ginContext *gin.Context) {
		err := check(ginContext.Request.Context())
		if err == nil {
			return
		}
		recordDenial(wideevent.FromContext(ginContext.Request.Context()), err)
		auth.WriteError(ginContext.Writer, err)
		ginContext.Abort()
	}
}

// RequireMethodPermission is Require(authorization.HasPermission(resource, auth.AccessForMethod(method)))
// evaluated per request: one gate for a route group where GET, HEAD and OPTIONS need read access on
// resource and every other method write access. Same recording and responses as Require.
func RequireMethodPermission(resource string) gin.HandlerFunc {
	requireRead := Require(authorization.HasPermission(resource, auth.AccessRead))
	requireWrite := Require(authorization.HasPermission(resource, auth.AccessWrite))
	return func(ginContext *gin.Context) {
		if auth.AccessForMethod(ginContext.Request.Method) == auth.AccessRead {
			requireRead(ginContext)
			return
		}
		requireWrite(ginContext)
	}
}

func recordDecision(we *wideevent.Event, prefix string, outcome auth.Outcome) {
	we.String(prefix+"provider", outcome.Provider).
		String(prefix+"action", string(outcome.Action)).
		String(prefix+"result", string(outcome.Result))
}

// recordOutcomeError records what the client was told and why. A denial's or failure's error itself
// becomes the request's error (recordRequestOutcome); a success with Err is a handled failure, so it is
// recorded here and marks the event degraded.
func recordOutcomeError(we *wideevent.Event, prefix string, outcome auth.Outcome) {
	if outcome.Err == nil {
		return
	}
	_, response := auth.ResponseFor(outcome.Err)
	we.String(prefix+"code", response.Code)
	if reason, _ := refusalReason(outcome.Err); reason != "" {
		we.String(prefix+"reason", reason)
	}
	switch outcome.Result {
	case auth.ResultError:
		we.Err(prefix+"error", outcome.Err)
	case auth.ResultSuccess, auth.ResultChallenge:
		we.Err(prefix+"error", outcome.Err).Bool("degraded", true)
	case auth.ResultDenied:
		// the refusal is recorded as the request's failure
	}
}

// recordIdentity records the subject of the identity that authenticated and, while it impersonates, the
// impersonated one's; the user ID only for the request's own outcome, since user.id has no prefix.
func recordIdentity(we *wideevent.Event, prefix string, identity *auth.Identity) {
	if identity == nil {
		return
	}
	we.String(prefix+"subject", identity.Real().Subject)
	if identity.Impersonator != nil {
		we.Bool(prefix+"impersonating", true).String(prefix+"impersonated_subject", identity.Subject)
	}
	if prefix == requestPrefix && identity.UserID != uuid.Nil {
		we.UserID(identity.UserID)
	}
}

// recordRequestOutcome sets the request outcome when the library answered the request: always for a
// denial or failure, for a success only when the action was the request itself (a login, a logout),
// not a per-request authentication or refresh that hands over to the application's handler.
func recordRequestOutcome(we *wideevent.Event, outcome auth.Outcome) {
	switch outcome.Result {
	case auth.ResultDenied, auth.ResultError:
		we.Failure(outcome.Err)
	case auth.ResultSuccess, auth.ResultChallenge:
		if outcome.Action != auth.ActionAuthenticate && outcome.Action != auth.ActionRefresh {
			we.Success()
		}
	}
}

// recordDenial records a refused authorization check. The reason of an error that is no *auth.Error
// is its message; such an error is an internal failure (500) and also recorded as authorization.error.
func recordDenial(we *wideevent.Event, err error) {
	reason, isRefusal := refusalReason(err)
	if !isRefusal {
		reason = err.Error()
	}
	we.Bool("authorization.denied", true)
	if reason != "" {
		we.String("authorization.reason", reason)
	}
	if status, _ := auth.ResponseFor(err); status == http.StatusInternalServerError {
		we.Err("authorization.error", err)
	}
	we.Failure(err)
}

// refusalReason returns the Reason of the *auth.Error in err and whether err carries one at all.
func refusalReason(err error) (string, bool) {
	var refusal *auth.Error
	if !errors.As(err, &refusal) {
		return "", false
	}
	return refusal.Reason, true
}
