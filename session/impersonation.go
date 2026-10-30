package session

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/govengers/auth"
	"github.com/govengers/auth/authorization"
	"github.com/govengers/auth/internal/failure"
	"github.com/govengers/auth/internal/httpjson"
	"github.com/govengers/auth/internal/redirect"
)

const (
	defaultImpersonationPathPrefix = "/auth/impersonation"
	defaultMaximumImpersonation    = time.Hour
)

// The client codes of the impersonation refusals.
const (
	codeAlreadyImpersonating = "already_impersonating"
	codeNotImpersonating     = "not_impersonating"
	codeUnknownTarget        = "unknown_impersonation_target"
	codeSelfImpersonation    = "self_impersonation"
)

// ImpersonationLoader returns the identity of the user subject names, as a login of that user would produce
// it (OnLogin applied), or nil without an error when there is none. ctx carries the impersonator's identity
// (auth.IdentityFrom), so a loader can refuse a target with an *auth.Error, e.g. one of another tenant.
// It must be safe for concurrent use.
type ImpersonationLoader func(ctx context.Context, subject string) (*auth.Identity, error)

// ImpersonatorOptions configures NewImpersonator.
type ImpersonatorOptions struct {
	Guard *Guard              // required; its Store holds the sessions, and Routes run behind its RequireAPI
	Load  ImpersonationLoader // required
	// Actor decides who may impersonate, evaluated against the impersonator's identity; default
	// authorization.IsAdmin().
	Actor authorization.Check
	// Target decides who may be impersonated, evaluated against the target's identity; default
	// authorization.Not(authorization.IsAdmin()), so nobody gains an admin's rights by impersonating one.
	Target          authorization.Check
	MaximumDuration time.Duration // default 1 h, at least 1 s; the Guard ends an impersonation that long after its start
	PathPrefix      string        // default "/auth/impersonation"; segments of A-Z a-z 0-9 . _ ~ -, no trailing "/"
	Observer        auth.Observer // optional
}

// Impersonator lets an identity act as another one in its own session. It is the only way to start or stop
// an impersonation: SaveIdentity and SwapIdentity refuse to. An impersonation needs an identity that passes
// Actor and is not impersonating already, and a target that Load returns, that passes Target, is active and
// is not the impersonator. It keeps the session (its cookie, lifetime and provider values) and ends when
// stopped, with the session, or MaximumDuration after its start, whichever comes first. It is safe for
// concurrent use.
type Impersonator struct {
	options ImpersonatorOptions
	store   *Store
}

// NewImpersonator validates options and returns an Impersonator working on a copy of them.
func NewImpersonator(options *ImpersonatorOptions) (*Impersonator, error) {
	if options == nil || options.Guard == nil || options.Load == nil {
		return nil, errors.New("session impersonator: Guard and Load are required")
	}
	resolved := *options
	if resolved.Actor == nil {
		resolved.Actor = authorization.IsAdmin()
	}
	if resolved.Target == nil {
		resolved.Target = authorization.Not(authorization.IsAdmin())
	}
	if resolved.MaximumDuration == 0 {
		resolved.MaximumDuration = defaultMaximumImpersonation
	}
	if resolved.MaximumDuration < time.Second {
		return nil, fmt.Errorf("session impersonator: MaximumDuration %s is below one second", resolved.MaximumDuration)
	}
	if resolved.PathPrefix == "" {
		resolved.PathPrefix = defaultImpersonationPathPrefix
	}
	if !redirect.IsPathPrefix(resolved.PathPrefix) {
		return nil, fmt.Errorf("session impersonator: PathPrefix %q must be a clean path below \"/\" of unreserved URL characters, without a trailing slash", resolved.PathPrefix)
	}
	return &Impersonator{options: resolved, store: resolved.Guard.options.Store}, nil
}

// Start makes the request's identity (auth.IdentityFrom, put there by the Guard) impersonate the identity
// Load returns for subject, in the request's session, and returns the impersonating identity. Refusals:
// no identity 401; already impersonating 409 already_impersonating; inactive 403; an empty subject 400; Actor's or Load's
// refusal; no such target 400 unknown_impersonation_target; the impersonator itself 400 self_impersonation;
// an inactive target 403; Target's refusal; a session that no longer holds the request's identity 409.
// It reports the outcome (Action impersonation_start) under the impersonator's provider.
func (i *Impersonator) Start(request *http.Request, subject string) (*auth.Identity, error) {
	ctx := request.Context()
	actor := auth.IdentityFrom(ctx)
	impersonated, err := i.start(request, actor, subject)
	outcome := auth.Outcome{Provider: providerOf(actor), Action: auth.ActionImpersonationStart, Identity: impersonated, Err: err}
	if err != nil {
		outcome.Identity = actor
		i.reportFailure(ctx, outcome)
		return nil, err
	}
	outcome.Result = auth.ResultSuccess
	i.report(ctx, outcome)
	return impersonated, nil
}

func (i *Impersonator) start(request *http.Request, actor *auth.Identity, subject string) (*auth.Identity, error) {
	ctx := request.Context()
	switch {
	case actor == nil:
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "no identity"}
	case actor.Impersonator != nil:
		return nil, &auth.Error{Kind: auth.ErrConflict, Code: codeAlreadyImpersonating, Reason: "impersonating already"}
	case !actor.Active:
		return nil, &auth.Error{Kind: auth.ErrForbidden, Reason: auth.ReasonInactive}
	case subject == "":
		return nil, &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "empty impersonation subject"}
	}
	if err := i.options.Actor(ctx); err != nil {
		return nil, err
	}
	target, err := i.options.Load(ctx, subject)
	if err != nil {
		return nil, fmt.Errorf("load impersonation target: %w", err)
	}
	if err := i.admitTarget(ctx, actor, target); err != nil {
		return nil, err
	}
	impersonated := target.Clone()
	impersonated.Impersonator = actor.Clone()
	current, err := i.store.Open(request)
	if err != nil {
		return nil, err
	}
	if err := current.replaceIdentity(ctx, actor, impersonated, i.store.now().Add(i.options.MaximumDuration)); err != nil {
		return nil, err
	}
	return impersonated, nil
}

// admitTarget refuses a target the actor must not impersonate.
func (i *Impersonator) admitTarget(ctx context.Context, actor, target *auth.Identity) error {
	switch {
	case target == nil:
		return &auth.Error{Kind: auth.ErrInvalidRequest, Code: codeUnknownTarget, Reason: "no impersonation target"}
	case target.Impersonator != nil:
		return errors.New("load impersonation target: the loaded identity impersonates another one")
	case sameUser(actor, target):
		return &auth.Error{Kind: auth.ErrInvalidRequest, Code: codeSelfImpersonation, Reason: "impersonation target is the impersonator"}
	case !target.Active:
		return &auth.Error{Kind: auth.ErrForbidden, Reason: "impersonation target " + auth.ReasonInactive}
	}
	return i.options.Target(auth.WithIdentity(ctx, target))
}

// sameUser reports whether two identities are the same user: same provider and subject, or the same
// application user ID.
func sameUser(first, second *auth.Identity) bool {
	return samePrincipal(first, second) || (first.UserID != uuid.Nil && first.UserID == second.UserID)
}

// Stop ends the impersonation of the request's identity (auth.IdentityFrom) in the request's session and
// returns the impersonator's identity as the session now holds it. Refusals: no identity 401; not
// impersonating 409 not_impersonating; a session that no longer holds the request's identity 409. It reports
// the outcome (Action impersonation_stop) under the impersonator's provider.
func (i *Impersonator) Stop(request *http.Request) (*auth.Identity, error) {
	ctx := request.Context()
	identity := auth.IdentityFrom(ctx)
	impersonator, err := i.stop(request, identity)
	outcome := auth.Outcome{Provider: providerOf(identity), Action: auth.ActionImpersonationStop, Identity: identity, Err: err}
	if err != nil {
		i.reportFailure(ctx, outcome)
		return nil, err
	}
	outcome.Result = auth.ResultSuccess
	i.report(ctx, outcome)
	return impersonator, nil
}

func (i *Impersonator) stop(request *http.Request, identity *auth.Identity) (*auth.Identity, error) {
	switch {
	case identity == nil:
		return nil, &auth.Error{Kind: auth.ErrUnauthenticated, Reason: "no identity"}
	case identity.Impersonator == nil:
		return nil, &auth.Error{Kind: auth.ErrConflict, Code: codeNotImpersonating, Reason: "not impersonating"}
	}
	current, err := i.store.Open(request)
	if err != nil {
		return nil, err
	}
	if err := current.replaceIdentity(request.Context(), identity, identity.Impersonator, time.Time{}); err != nil {
		return nil, err
	}
	return identity.Impersonator, nil
}

// impersonationRequest is the body of POST {PathPrefix}.
type impersonationRequest struct {
	Subject string `json:"subject"`
}

// Routes returns POST {PathPrefix} (JSON body {"subject": "..."}: Start, answers 200 with the impersonating
// identity's auth.IdentityResponse) and DELETE {PathPrefix} (Stop, answers 200 with the impersonator's),
// both behind the Guard's RequireAPI. Register them with auth.RegisterRoutes or ginadapter.RegisterRoutes.
// The POST requires Content-Type application/json and DELETE is no simple request, so a cross-site page
// cannot send either without a CORS preflight.
func (i *Impersonator) Routes() []auth.Route {
	requireAPI := i.options.Guard.RequireAPI()
	return []auth.Route{
		{Method: http.MethodPost, Path: i.options.PathPrefix, Handler: requireAPI(http.HandlerFunc(i.handleStart))},
		{Method: http.MethodDelete, Path: i.options.PathPrefix, Handler: requireAPI(http.HandlerFunc(i.handleStop))},
	}
}

func (i *Impersonator) handleStart(writer http.ResponseWriter, request *http.Request) {
	var body impersonationRequest
	if err := httpjson.Decode(writer, request, &body); err != nil {
		err = &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed impersonation request", Err: err}
		actor := auth.IdentityFrom(request.Context())
		i.reportFailure(request.Context(), auth.Outcome{Provider: providerOf(actor), Action: auth.ActionImpersonationStart, Identity: actor, Err: err})
		auth.WriteError(writer, err)
		return
	}
	identity, err := i.Start(request, body.Subject)
	writeIdentity(writer, identity, err)
}

func (i *Impersonator) handleStop(writer http.ResponseWriter, request *http.Request) {
	identity, err := i.Stop(request)
	writeIdentity(writer, identity, err)
}

// writeIdentity answers identity as auth.IdentityResponse, or err.
func writeIdentity(writer http.ResponseWriter, identity *auth.Identity, err error) {
	if err != nil {
		auth.WriteError(writer, err)
		return
	}
	httpjson.Write(writer, http.StatusOK, auth.NewIdentityResponse(identity))
}

// providerOf is the Outcome.Provider of an impersonation outcome: the impersonator's provider, "session"
// without an identity.
func providerOf(identity *auth.Identity) string {
	if identity == nil {
		return auth.ProviderSession
	}
	return identity.Real().Provider
}

func (i *Impersonator) reportFailure(ctx context.Context, outcome auth.Outcome) {
	outcome.Result = failure.Result(outcome.Err)
	i.report(ctx, outcome)
}

func (i *Impersonator) report(ctx context.Context, outcome auth.Outcome) {
	if i.options.Observer != nil {
		i.options.Observer(ctx, outcome)
	}
}
