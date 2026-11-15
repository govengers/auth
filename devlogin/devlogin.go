// Package devlogin is a one-click login for local development: a list of the application's users and a login
// as any of them, without a credential. It must never be enabled outside development; see New for the guards.
// Its Provider is safe for concurrent use.
package devlogin

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/failure"
	"github.com/govengers/auth/internal/fetchmetadata"
	"github.com/govengers/auth/internal/httpjson"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/session"
)

const (
	defaultPathPrefix = "/auth/dev"
	// logoutTimeout bounds logout's session reads and End, which a disconnecting client cannot cancel.
	logoutTimeout = 10 * time.Second
)

// Client codes of the refusals (stable API for frontends).
const (
	codeNotLocal    = "dev_login_not_local"
	codeUnknownUser = "unknown_dev_user"
)

// forwardingHeaders are set by reverse proxies; a request carrying one came through a proxy, whatever its peer.
var forwardingHeaders = []string{"Forwarded", "Via", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Port", "X-Forwarded-Proto", "X-Forwarded-Server", "X-Real-IP"}

// User is one entry of the login list.
type User struct {
	ID          string `json:"id"`                    // what POST {prefix}/login sends back and Load receives
	Name        string `json:"name"`                  // shown on the button
	Description string `json:"description,omitempty"` // a hint such as "admin" or "no projects"
}

// UserLister returns the users the login list offers. It must be safe for concurrent use.
type UserLister func(ctx context.Context) ([]User, error)

// Loader returns the identity a login of the user id gets, as the application's other logins would build it
// (UserID, roles, Active), or nil without an error when there is no such user. Provider and Subject are
// replaced by "dev_login" (auth.ProviderDev) and id. An *auth.Error refuses the login with its status. It must be safe for concurrent use.
type Loader func(ctx context.Context, id string) (*auth.Identity, error)

// Options configures New.
type Options struct {
	// Enabled must be true: New refuses to build a provider otherwise, so an application wires the routes only
	// behind its own development flag and a forgotten flag cannot turn them on.
	Enabled  bool
	Sessions *session.Store // required
	Users    UserLister     // required
	Load     Loader         // required
	// PathPrefix defaults to "/auth/dev"; segments of A-Z a-z 0-9 . _ ~ -, no trailing "/".
	PathPrefix string
	// AllowRemote drops the peer and forwarding-header parts of the local-only check: by default every route
	// refuses a request whose peer is not a loopback address or that carries a proxy's forwarding header. Set it
	// only for a development stack where the browser reaches the server through a container network (docker
	// port publishing, a devcontainer) or a local proxy. The Host check stays: it is the DNS-rebinding defence.
	AllowRemote bool
	// AllowedHosts are host names (without port, case-insensitive) the Host check accepts besides localhost,
	// *.localhost and loopback addresses, e.g. "app.test" for a stack behind a named local proxy.
	AllowedHosts []string
	Observer     auth.Observer // optional; every request is reported under provider "dev_login"
}

// Provider serves the development login: GET {prefix}/users lists the users, POST {prefix}/login with
// {"id": "<user ID>"} starts a normal session for one of them, POST {prefix}/logout ends the request's session.
// Its routes read the session themselves, so they need no Guard in front. It is safe for concurrent use.
type Provider struct {
	options  Options
	reporter *failure.Reporter
}

// New validates options and returns a Provider working on a copy of them. It refuses options without Enabled.
// An application calls it only in development, e.g. behind a configuration flag that also requires an
// insecure (plain HTTP) session cookie; see docs/wiki/Dev-Login.md.
func New(options *Options) (*Provider, error) {
	if options == nil || !options.Enabled {
		return nil, errors.New("dev login: Enabled is false; build the provider only in local development")
	}
	if options.Sessions == nil || options.Users == nil || options.Load == nil {
		return nil, errors.New("dev login: options need Sessions, Users and Load")
	}
	resolved := *options
	if resolved.PathPrefix == "" {
		resolved.PathPrefix = defaultPathPrefix
	}
	if !redirect.IsPathPrefix(resolved.PathPrefix) {
		return nil, fmt.Errorf("dev login: PathPrefix %q must be a clean path below \"/\" of unreserved URL characters, without a trailing slash", resolved.PathPrefix)
	}
	resolved.AllowedHosts = make([]string, 0, len(options.AllowedHosts))
	for _, host := range options.AllowedHosts {
		if host == "" || strings.ContainsAny(host, ":/ ") {
			return nil, fmt.Errorf("dev login: AllowedHosts entry %q must be a host name without port", host)
		}
		resolved.AllowedHosts = append(resolved.AllowedHosts, normalizeHost(host))
	}
	reporter, err := failure.NewReporter(&failure.ReporterOptions{Provider: auth.ProviderDev, Observer: resolved.Observer})
	if err != nil {
		return nil, fmt.Errorf("dev login: %w", err)
	}
	return &Provider{options: resolved, reporter: reporter}, nil
}

// Name returns "dev_login" (auth.ProviderDev), the Identity.Provider of every identity this provider creates.
func (p *Provider) Name() string {
	return auth.ProviderDev
}

// Routes returns the provider's endpoints below PathPrefix. Register them with auth.RegisterRoutes or
// ginadapter.RegisterRoutes.
func (p *Provider) Routes() []auth.Route {
	return []auth.Route{
		p.route(http.MethodGet, "/users", auth.ActionListUsers, p.users),
		p.route(http.MethodPost, "/login", auth.ActionLogin, p.login),
		p.route(http.MethodPost, "/logout", auth.ActionLogout, p.logout),
	}
}

// answer is what a handler returns: a JSON body (nil: 204), the identity concerned, the refusal or failure,
// and a handled failure that only degrades a success.
type answer struct {
	body     any
	identity *auth.Identity
	err      error
	degraded error
}

func (p *Provider) route(method, path string, action auth.Action, handle func(writer http.ResponseWriter, request *http.Request) answer) auth.Route {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := request.Context()
		if err := p.checkLocal(request); err != nil {
			p.reporter.Refuse(ctx, writer, auth.Outcome{Action: action, Err: err})
			return
		}
		result := handle(writer, request)
		if result.err != nil {
			p.reporter.Refuse(ctx, writer, auth.Outcome{Action: action, Err: result.err, Identity: result.identity})
			return
		}
		if result.body == nil {
			writer.Header().Set("Cache-Control", "no-store")
			writer.WriteHeader(http.StatusNoContent)
		} else {
			httpjson.Write(writer, http.StatusOK, result.body)
		}
		p.reporter.Report(ctx, auth.Outcome{Action: action, Result: auth.ResultSuccess, Identity: result.identity, Err: result.degraded})
	})
	return auth.Route{Method: method, Path: p.options.PathPrefix + path, Handler: handler}
}

// checkLocal refuses a request that did not come straight from this machine (AllowRemote: whose Host does not
// name it). It is a seat belt, not a boundary: a reverse proxy on the same host that rewrites Host to its
// loopback upstream and sets no forwarding header (httputil.ReverseProxy with Rewrite, nginx proxy_pass
// without proxy_set_header, a dev server proxy with changeOrigin listening on the LAN) passes it for every
// client it serves. Enabled stays the guard that matters.
func (p *Provider) checkLocal(request *http.Request) error {
	if p.isLocal(request) {
		return nil
	}
	return &auth.Error{Kind: auth.ErrForbidden, Code: codeNotLocal, Reason: "dev login from a non-local request"}
}

func (p *Provider) isLocal(request *http.Request) bool {
	if !p.isLocalHost(request.Host) {
		return false
	}
	if p.options.AllowRemote {
		return true
	}
	peer, _, err := net.SplitHostPort(request.RemoteAddr)
	if err != nil || !isLoopback(peer) {
		return false
	}
	for _, header := range forwardingHeaders {
		if len(request.Header.Values(header)) > 0 {
			return false
		}
	}
	return true
}

// isLocalHost reports whether the Host header names this machine or one of AllowedHosts. A DNS rebinding page
// reaches a local server under its own host name, so a server answering any Host would hand it the user list
// and a session.
func (p *Provider) isLocalHost(host string) bool {
	if name, _, err := net.SplitHostPort(host); err == nil {
		host = name
	}
	host = normalizeHost(host)
	return host == "localhost" || strings.HasSuffix(host, ".localhost") || isLoopback(strings.Trim(host, "[]")) ||
		slices.Contains(p.options.AllowedHosts, host)
}

func normalizeHost(host string) string {
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func isLoopback(host string) bool {
	address, err := netip.ParseAddr(host)
	return err == nil && address.Unmap().IsLoopback()
}

type usersResponse struct {
	Users []User `json:"users"`
}

func (p *Provider) users(_ http.ResponseWriter, request *http.Request) answer {
	users, err := p.options.Users(request.Context())
	if err != nil {
		return answer{err: fmt.Errorf("list dev users: %w", err)}
	}
	if users == nil {
		users = []User{}
	}
	return answer{body: usersResponse{Users: users}}
}

type loginRequest struct {
	ID string `json:"id"`
}

// login starts a fresh session (revoking the request's current one) for the identity Load returns.
func (p *Provider) login(writer http.ResponseWriter, request *http.Request) answer {
	if err := fetchmetadata.RefuseCrossSite(request); err != nil {
		return answer{err: err}
	}
	var body loginRequest
	if err := httpjson.Decode(writer, request, &body); err != nil {
		return answer{err: &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "malformed dev login request", Err: err}}
	}
	if body.ID == "" {
		return answer{err: &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "empty user ID"}}
	}
	ctx := request.Context()
	loaded, err := p.options.Load(ctx, body.ID)
	if err != nil {
		return answer{err: fmt.Errorf("load dev user: %w", err)}
	}
	if loaded == nil {
		return answer{err: &auth.Error{Kind: auth.ErrInvalidRequest, Code: codeUnknownUser, Reason: "unknown dev user"}}
	}
	identity := loaded.Clone()
	identity.Provider = auth.ProviderDev
	identity.Subject = body.ID
	if !identity.Active {
		return answer{identity: identity, err: &auth.Error{Kind: auth.ErrForbidden, Reason: auth.ReasonInactive}}
	}
	current, err := p.options.Sessions.Start(ctx, writer, request)
	if err != nil {
		return answer{identity: identity, err: fmt.Errorf("start dev session: %w", err)}
	}
	if err := current.SaveIdentity(ctx, identity); err != nil {
		return answer{identity: identity, err: fmt.Errorf("save dev session identity: %w", err)}
	}
	return answer{body: auth.NewIdentityResponse(identity), identity: identity}
}

// logout ends the request's session, whatever it holds; a cross-site request (logout CSRF) is refused first.
func (p *Provider) logout(writer http.ResponseWriter, request *http.Request) answer {
	if err := fetchmetadata.RefuseCrossSite(request); err != nil {
		return answer{err: err}
	}
	ctx, cancel := context.WithTimeout(context.WithoutCancel(request.Context()), logoutTimeout)
	defer cancel()
	var identity *auth.Identity
	current, readError := p.options.Sessions.Open(request)
	if readError == nil {
		identity, readError = current.Identity(ctx)
	}
	if readError = failure.UnlessAbsent(readError); readError != nil {
		readError = fmt.Errorf("read dev session identity: %w", readError)
	}
	if err := p.options.Sessions.End(ctx, writer, request); err != nil {
		return answer{identity: identity, err: errors.Join(fmt.Errorf("end dev session: %w", err), readError)}
	}
	return answer{identity: identity, degraded: readError}
}
