package session

import (
	"bytes"
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
	defaultRefreshInterval      = time.Minute
	defaultMaximumUnverifiedAge = time.Hour
	// unverifiedReason is the Reason of the refusal that ends a session whose refreshes kept failing.
	unverifiedReason = "identity could not be verified"
	// refreshTimeout bounds a refresh, which runs without the request's cancellation (as ending a session
	// does): a GitHub refresh may page through the teams.
	refreshTimeout = 30 * time.Second
)

// Refresher re-validates identities of one provider. The Guard calls it for identities whose last
// refresh is older than RefreshInterval, always with the real identity (identity.Real()).
// Return a copy with provider-owned fields updated; keep every other field (roles set by OnLogin etc.).
// ErrUnauthenticated or ErrForbidden end the session (a Refresher that is also a Revoker is called first); any other error keeps the identity (degraded) until
// the last successful verification is older than GuardOptions.MaximumUnverifiedAge. Refresh runs without the request's cancellation, bounded by 30 s. Implementations must be safe for
// concurrent use.
type Refresher interface {
	Name() string // the Identity.Provider it refreshes
	Refresh(ctx context.Context, current Session, identity *auth.Identity) (*auth.Identity, error)
}

// Revoker is optionally implemented by a Refresher whose provider holds state for a session at the
// identity provider, such as GitHub's OAuth token. Before the Guard ends a session whose refresh it
// refused (a refusal of the Refresher, or a failure lasting longer than MaximumUnverifiedAge), it calls
// RevokeSession with the session, which still holds the provider's values, on a context without the
// request's cancellation and with its own 10 s timeout. An error only degrades the outcome: the session
// ends either way. A session that expires (MaximumAge) or ends otherwise is not seen by the Guard, so it is
// not called then. Implementations must be safe for concurrent use.
type Revoker interface {
	RevokeSession(ctx context.Context, current Session) error
}

// GuardOptions configures NewGuard.
type GuardOptions struct {
	Store            *Store        // required
	LoginURL         string        // RequireUI target; absolute http(s) URL or path starting with "/", without a fragment; default "/"
	ReturnPathHeader string        // header carrying the original request URI (forward auth: "X-Forwarded-Uri"); default: request.URL.RequestURI()
	Refreshers       []Refresher   // optional; names must be unique
	RefreshInterval  time.Duration // default 1 min
	// MaximumUnverifiedAge bounds a degraded refresh: a refresh failing for longer than this since the login
	// or the last successful refresh ends the session. Default 1 h (RefreshInterval when that is longer); at
	// least RefreshInterval.
	MaximumUnverifiedAge time.Duration
	Observer             auth.Observer // optional
}

// Guard authenticates requests by their session: it puts the stored identity into the request
// context or refuses the request. An impersonation whose MaximumDuration is up ends on the next request, which
// then carries the impersonator's identity. One Guard serves every provider. It is safe for concurrent use.
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
		return nil, errors.New("session guard: LoginURL must be an absolute http(s) URL or a path starting with \"/\", without a fragment")
	}
	if resolved.RefreshInterval == 0 {
		resolved.RefreshInterval = defaultRefreshInterval
	}
	if resolved.RefreshInterval < 0 {
		return nil, fmt.Errorf("session guard: RefreshInterval %s is negative", resolved.RefreshInterval)
	}
	if resolved.MaximumUnverifiedAge == 0 {
		resolved.MaximumUnverifiedAge = max(defaultMaximumUnverifiedAge, resolved.RefreshInterval)
	}
	if resolved.MaximumUnverifiedAge < resolved.RefreshInterval {
		return nil, fmt.Errorf("session guard: MaximumUnverifiedAge %s is below RefreshInterval %s", resolved.MaximumUnverifiedAge, resolved.RefreshInterval)
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
			identity, err := g.authenticate(request.Context(), request, func(ctx context.Context) error {
				return g.options.Store.End(ctx, writer, request)
			})
			if err != nil {
				refuse(writer, request, err)
				return
			}
			next.ServeHTTP(writer, request.WithContext(auth.WithIdentity(request.Context(), identity)))
		})
	}
}

// Identify returns the identity of the request's session without writing a response or a cookie: the
// same lookup RequireAPI does, for a caller that has no response any more, such as a WebSocket re-validating
// the cookies of its upgrade request for as long as the socket lives. It opens the session from the
// request's cookies, ends an impersonation whose MaximumDuration is up (the identity is then the
// impersonator's), runs a due refresh through the Refresher and reports to the Observer, exactly as the
// middleware does; all of that writes the Store, never a cookie. The errors are the middleware's refusals:
// an *auth.Error of kind ErrUnauthenticated without a valid session cookie or for an ended or expired
// session, the Refresher's ErrUnauthenticated or ErrForbidden for a refused refresh, any other error for a
// failing backend. A refused refresh ends the session in the Store as the middleware would; only the cookie
// stays with the client, naming a revoked session that every later request is refused for, until a login
// or logout replaces it or its Max-Age runs out.
// An identity already in ctx is not consulted: Identify is a lookup, not middleware. The lookup runs on
// ctx, not on the request's context, which an upgrade request no longer has once its handler returned.
func (g *Guard) Identify(ctx context.Context, request *http.Request) (*auth.Identity, error) {
	return g.authenticate(ctx, request, func(ctx context.Context) error {
		return g.options.Store.revokeRequestSession(ctx, request)
	})
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

// sessionEnder ends the request's session when its refresh was refused: the middleware expires the cookie as
// well (Store.End), Identify only revokes the session.
type sessionEnder func(ctx context.Context) error

// authenticate is the lookup behind the middleware and Identify, on ctx (the middleware's request context,
// Identify's own) with end for a refused refresh.
func (g *Guard) authenticate(ctx context.Context, request *http.Request, end sessionEnder) (*auth.Identity, error) {
	current, err := g.options.Store.Open(request)
	if err != nil {
		return nil, g.reportFailure(ctx, auth.Outcome{Provider: auth.ProviderSession, Action: auth.ActionAuthenticate, Err: err})
	}
	stored, err := current.envelope(ctx)
	if err != nil {
		return nil, g.reportFailure(ctx, auth.Outcome{Provider: auth.ProviderSession, Action: auth.ActionAuthenticate, Err: err})
	}
	if stored.impersonationOver(g.now()) {
		ended, err := current.endImpersonation(ctx, stored)
		if err != nil {
			return nil, g.reportFailure(ctx, auth.Outcome{Provider: stored.Identity.Real().Provider, Action: auth.ActionAuthenticate, Err: err, Identity: stored.Identity})
		}
		stored = ended
	}
	identity := stored.Identity
	if g.refreshDue(stored) {
		if identity, err = g.refresh(ctx, current, stored, end); err != nil {
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

// refresh claims the due refresh, runs the real identity's Refresher, saves the outcome and reports it
// (Action refresh). The claim saves the moved refreshedAt before the Refresher runs, so requests reading
// the session meanwhile find it fresh: one Refresher call per interval. A request losing the claim (another
// one claimed or saved first) continues with the identity it read. A refusal ends the session (when that
// fails, the request fails with 500, the outcome is an error and the claim is released, as the session
// stays usable); any other
// failure keeps the identity and is reported as a degraded success (Result success with Err set): the
// request is still answered. Once the identity was last verified longer than MaximumUnverifiedAge ago, such
// a failure is a refusal as well. The save swaps against the claim: when another request saved the session
// meanwhile, that save wins and the request continues with it. The claim, the Refresher and everything
// after them run without the request's cancellation: a client aborting each due refresh would otherwise
// keep a refused identity alive with the claim taken. A claim the backend failed is read back: when the
// stored value is the claim, it committed with its reply lost and the refresh runs (degraded); otherwise
// the request fails without calling the provider, so a backend failing writes costs no provider call.
func (g *Guard) refresh(ctx context.Context, current Session, stored identityEnvelope, end sessionEnder) (*auth.Identity, error) {
	refreshContext, cancel := context.WithTimeout(context.WithoutCancel(ctx), refreshTimeout)
	defer cancel()
	realIdentity := stored.Identity.Real()
	outcome := auth.Outcome{Provider: realIdentity.Provider, Action: auth.ActionRefresh, Identity: stored.Identity}
	claimed, owned, err := g.claim(refreshContext, current, stored)
	switch {
	case !owned && err != nil:
		outcome.Err = err
		return nil, g.reportFailure(ctx, outcome)
	case !owned:
		return stored.Identity, nil
	}
	outcome.Err = err // a claim that committed although the backend failed it: refreshed, degraded
	refreshed, err := g.refreshers[realIdentity.Provider].Refresh(refreshContext, current, realIdentity.Clone())
	err = g.refreshError(claimed, realIdentity.Provider, refreshed, err)
	switch {
	case isRefusal(err):
		revokeError := g.revokeAtProvider(ctx, realIdentity.Provider, current) // before End, which deletes what it reads
		outcome.Err = errors.Join(err, revokeError)
		if endError := g.endRefusedSession(refreshContext, end, current, claimed, stored.RefreshedAt); endError != nil {
			// The session stays usable: a 500, not the refusal (kept as text only, so it cannot decide the answer).
			outcome.Err = errors.Join(fmt.Errorf("end session refused by its refresh (%s): %w", err.Error(), endError), revokeError)
		}
		return nil, g.reportFailure(ctx, outcome)
	case err != nil:
		outcome.Err = err
	default:
		claimed.Identity = impersonation.WithReal(claimed.Identity, refreshed)
		claimed.VerifiedAt = g.now()
	}
	claimed.RefreshedAt = g.now()
	saved, swapped, err := current.swapEnvelope(refreshContext, claimed)
	if err == nil && !swapped {
		saved, err = current.envelope(refreshContext)
	}
	if err != nil {
		outcome.Err = errors.Join(outcome.Err, err)
		return nil, g.reportFailure(ctx, outcome)
	}
	outcome.Identity, outcome.Result = saved.Identity, auth.ResultSuccess
	g.report(ctx, outcome)
	return saved.Identity, nil
}

// claim takes the due refresh by swapping in stored with refreshedAt moved to now and returns the claimed
// envelope. owned reports whether this request runs the refresh: with err, the backend failed the claim but
// it committed (read back: sealed values never repeat, so only its reply was lost); err without owned is the
// failure to answer with; neither means another request claimed or saved first.
func (g *Guard) claim(ctx context.Context, current Session, stored identityEnvelope) (claimed identityEnvelope, owned bool, err error) {
	stored.RefreshedAt = g.now()
	claimed, swapped, err := current.swapEnvelope(ctx, stored)
	if err == nil || claimed.sealed == nil { // answered, or nothing sent (an expired session, a sealing failure)
		return claimed, swapped, err
	}
	readBack, readError := current.envelope(ctx)
	if readError == nil && bytes.Equal(readBack.sealed, claimed.sealed) {
		return claimed, true, err
	}
	return claimed, false, errors.Join(err, readError)
}

// refreshError is the error of a refresh that returned refreshed and err: nil on success, a missing
// identity, err, or, when the identity was last verified longer than MaximumUnverifiedAge ago, a refusal
// with err as its cause, so a lasting failure cannot keep stale teams and roles until MaximumAge.
func (g *Guard) refreshError(claimed identityEnvelope, provider string, refreshed *auth.Identity, err error) error {
	if err == nil && refreshed == nil {
		err = fmt.Errorf("refresher %q returned no identity", provider)
	}
	if err == nil || isRefusal(err) || g.now().Sub(claimed.verifiedAt()) <= g.options.MaximumUnverifiedAge {
		return err
	}
	return &auth.Error{Kind: auth.ErrUnauthenticated, Reason: unverifiedReason, Err: err}
}

// isRefusal reports whether a Refresher refused the identity, which ends the session.
func isRefusal(err error) bool {
	return errors.Is(err, auth.ErrUnauthenticated) || errors.Is(err, auth.ErrForbidden)
}

// revokeAtProvider lets provider's Refresher, when it is a Revoker, revoke what it holds for the session
// at the identity provider. It runs detached and bounded on its own, so neither a disconnecting client nor
// a refresh that used up its timeout skips it.
func (g *Guard) revokeAtProvider(ctx context.Context, provider string, current Session) error {
	revoker, isRevoker := g.refreshers[provider].(Revoker)
	if !isRevoker {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), revokeTimeout)
	defer cancel()
	if err := revoker.RevokeSession(ctx, current); err != nil {
		return fmt.Errorf("revoke session at provider %q: %w", provider, err)
	}
	return nil
}

// endRefusedSession ends the session whose refresh was refused through end and returns the error of ending it. When
// that fails, the session stays usable, so it releases the claim (refreshedAt back to readAt): the next
// request refreshes (and fails) again instead of passing on it.
func (g *Guard) endRefusedSession(ctx context.Context, end sessionEnder, current Session, claimed identityEnvelope, readAt time.Time) error {
	if err := end(ctx); err != nil {
		claimed.RefreshedAt = readAt
		_, _, _ = current.swapEnvelope(ctx, claimed) // best effort: the request is a 500 already
		return err
	}
	return nil
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
