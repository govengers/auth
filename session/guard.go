package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/failure"
	"github.com/govengers/auth/internal/impersonation"
	"github.com/govengers/auth/internal/redirect"
)

const (
	defaultRefreshInterval = time.Minute
	// sessionProvider is the Outcome.Provider when the Guard finds no identity.
	sessionProvider = "session"
)

// Refresher re-validates identities of one provider. The Guard calls it for identities whose last
// refresh is older than RefreshInterval, always with the real identity (identity.Real()).
// Return a copy with provider-owned fields updated; keep every other field (roles set by OnLogin etc.).
// ErrUnauthenticated or ErrForbidden end the session; any other error keeps the identity (degraded).
// Implementations must be safe for concurrent use.
type Refresher interface {
	Name() string // the Identity.Provider it refreshes
	Refresh(ctx context.Context, current Session, identity *auth.Identity) (*auth.Identity, error)
}

// GuardOptions configures NewGuard.
type GuardOptions struct {
	Store            *Store        // required
	LoginURL         string        // RequireUI target; absolute http(s) URL or path starting with "/"; default "/"
	ReturnPathHeader string        // header carrying the original request URI (forward auth: "X-Forwarded-Uri"); default: request.URL.RequestURI()
	Refreshers       []Refresher   // optional; names must be unique
	RefreshInterval  time.Duration // default 1 min
	Observer         auth.Observer // optional
}

// Guard authenticates requests by their session: it puts the stored identity into the request
// context or refuses the request. One Guard serves every provider. It is safe for concurrent use.
type Guard struct {
	options    GuardOptions
	refreshers map[string]Refresher
	now        func() time.Time
}

type refusalWriter func(writer http.ResponseWriter, request *http.Request, err error)

// NewGuard validates options and returns a Guard working on a copy of them.
func NewGuard(options *GuardOptions) (*Guard, error) {
	if options == nil || options.Store == nil {
		return nil, errors.New("session guard: Store is required")
	}
	resolved := *options
	if resolved.LoginURL == "" {
		resolved.LoginURL = "/"
	}
	if !redirect.IsTarget(resolved.LoginURL) {
		return nil, errors.New("session guard: LoginURL must be an absolute http(s) URL or a path starting with \"/\"")
	}
	if resolved.RefreshInterval == 0 {
		resolved.RefreshInterval = defaultRefreshInterval
	}
	if resolved.RefreshInterval < 0 {
		return nil, fmt.Errorf("session guard: RefreshInterval %s is negative", resolved.RefreshInterval)
	}
	refreshers, err := refreshersByName(resolved.Refreshers)
	if err != nil {
		return nil, err
	}
	resolved.Refreshers = nil
	return &Guard{options: resolved, refreshers: refreshers, now: time.Now}, nil
}

func refreshersByName(refreshers []Refresher) (map[string]Refresher, error) {
	byName := make(map[string]Refresher, len(refreshers))
	for _, refresher := range refreshers {
		if refresher == nil || refresher.Name() == "" {
			return nil, errors.New("session guard: every Refresher needs a name")
		}
		if _, found := byName[refresher.Name()]; found {
			return nil, fmt.Errorf("session guard: two Refreshers are named %q", refresher.Name())
		}
		byName[refresher.Name()] = refresher
	}
	return byName, nil
}

// RequireAPI refuses unauthenticated requests with 401 JSON, forbidden ones with 403 JSON.
// A request that already carries an identity (e.g. from an API key) passes untouched.
func (g *Guard) RequireAPI() func(http.Handler) http.Handler {
	return g.require(func(writer http.ResponseWriter, _ *http.Request, err error) {
		auth.WriteError(writer, err)
	})
}

// RequireUI redirects unauthenticated requests 302 to LoginURL?return_to=<path> (path omitted when unsafe); forbidden ones get 403 JSON (a redirect would loop).
// A request that already carries an identity (e.g. from an API key) passes untouched.
func (g *Guard) RequireUI() func(http.Handler) http.Handler {
	return g.require(g.redirectToLogin)
}

func (g *Guard) require(refuse refusalWriter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			if auth.IdentityFrom(request.Context()) != nil {
				next.ServeHTTP(writer, request)
				return
			}
			identity, err := g.authenticate(writer, request)
			if err != nil {
				refuse(writer, request, err)
				return
			}
			next.ServeHTTP(writer, request.WithContext(auth.WithIdentity(request.Context(), identity)))
		})
	}
}

func (g *Guard) redirectToLogin(writer http.ResponseWriter, request *http.Request, err error) {
	if status, _ := auth.ResponseFor(err); status != http.StatusUnauthorized {
		auth.WriteError(writer, err)
		return
	}
	redirect.To(writer, redirect.LoginLocation(g.options.LoginURL, g.returnPath(request)))
}

// returnPath is the safe original request path, or "" when it is not safe.
func (g *Guard) returnPath(request *http.Request) string {
	source := request.URL.RequestURI()
	if g.options.ReturnPathHeader != "" {
		source = request.Header.Get(g.options.ReturnPathHeader)
	}
	returnPath, _ := redirect.SafeReturnPath(source)
	return returnPath
}

func (g *Guard) authenticate(writer http.ResponseWriter, request *http.Request) (*auth.Identity, error) {
	ctx := request.Context()
	current, err := g.options.Store.Open(request)
	if err != nil {
		return nil, g.reportFailure(ctx, auth.Outcome{Provider: sessionProvider, Action: auth.ActionAuthenticate, Err: err})
	}
	stored, err := current.envelope(ctx)
	if err != nil {
		return nil, g.reportFailure(ctx, auth.Outcome{Provider: sessionProvider, Action: auth.ActionAuthenticate, Err: err})
	}
	identity := stored.Identity
	if g.refreshDue(stored) {
		if identity, err = g.refresh(writer, request, current, stored); err != nil {
			return nil, err
		}
	}
	g.report(ctx, auth.Outcome{Provider: identity.Real().Provider, Action: auth.ActionAuthenticate, Result: auth.ResultSuccess, Identity: identity})
	return identity, nil
}

func (g *Guard) refreshDue(stored identityEnvelope) bool {
	_, found := g.refreshers[stored.Identity.Real().Provider]
	return found && g.now().Sub(stored.RefreshedAt) > g.options.RefreshInterval
}

// refresh runs the real identity's Refresher, saves the outcome and reports it (Action refresh). A
// refusal ends the session; any other failure keeps the identity, only moves refreshedAt and is
// reported as a degraded success (Result success with Err set): the request is still answered.
func (g *Guard) refresh(writer http.ResponseWriter, request *http.Request, current Session, stored identityEnvelope) (*auth.Identity, error) {
	ctx := request.Context()
	realIdentity := stored.Identity.Real()
	outcome := auth.Outcome{Provider: realIdentity.Provider, Action: auth.ActionRefresh, Identity: stored.Identity}
	refreshed, err := g.refreshers[realIdentity.Provider].Refresh(ctx, current, realIdentity.Clone())
	switch {
	case errors.Is(err, auth.ErrUnauthenticated) || errors.Is(err, auth.ErrForbidden):
		outcome.Err = errors.Join(err, g.options.Store.End(ctx, writer, request))
		return nil, g.reportFailure(ctx, outcome)
	case err != nil:
		outcome.Err = err
	case refreshed == nil:
		outcome.Err = fmt.Errorf("refresher %q returned no identity", realIdentity.Provider)
	default:
		stored.Identity = impersonation.WithReal(stored.Identity, refreshed)
	}
	stored.RefreshedAt = g.now()
	if err := current.saveEnvelope(ctx, stored); err != nil {
		outcome.Err = errors.Join(outcome.Err, err)
		return nil, g.reportFailure(ctx, outcome)
	}
	outcome.Identity, outcome.Result = stored.Identity, auth.ResultSuccess
	g.report(ctx, outcome)
	return stored.Identity, nil
}

// reportFailure reports outcome as denied (a refusal) or error (anything answered with 500) and returns its Err.
func (g *Guard) reportFailure(ctx context.Context, outcome auth.Outcome) error {
	outcome.Result = failure.Result(outcome.Err)
	g.report(ctx, outcome)
	return outcome.Err
}

func (g *Guard) report(ctx context.Context, outcome auth.Outcome) {
	if g.options.Observer != nil {
		g.options.Observer(ctx, outcome)
	}
}
