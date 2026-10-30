// Package forwardauth is the server of the forward-auth binary (cmd/forwardauth): the gin engine with
// the forward-auth checks Traefik calls, the provider routes, JWKS, identity, health and readiness
// endpoints, wide events and HTTP metrics on every request, and the graceful run of the public and the
// metrics listener.
package forwardauth

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"regexp"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	wideevent "github.com/mxcd/go-wide-event-logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/ginadapter"
	"github.com/govengers/auth/internal/httpjson"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/jwt"
	"github.com/govengers/auth/session"
)

const (
	defaultJWTHeader      = "Authorization"
	bearerPrefix          = "Bearer "
	readinessCheckTimeout = 2 * time.Second
	shutdownTimeout       = 20 * time.Second // below the 30 s default termination grace period [LAY-003]
	maximumHeaderBytes    = 64 << 10

	// MaximumPort is the highest TCP port.
	MaximumPort = 65535

	// MaximumShutdownDelay keeps ShutdownDelay plus the 20 s drain within the 30 s default termination
	// grace period of a pod [LAY-003].
	MaximumShutdownDelay = 10 * time.Second
)

// errNoRoute is the failure of a request no route matches: recorded, so the sampler keeps path scans and
// a wrong Traefik address [LOG-002, LOG-011].
var errNoRoute = errors.New("no route")

// headerNamePattern is an RFC 9110 field name (a token); net/http silently drops a header with any other name.
var headerNamePattern = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+.^_`|~-]+$")

// ServerOptions configure a Server. main fills them from the configuration.
type ServerOptions struct {
	Version           string
	Port, MetricsPort int                             // 0 picks a free port (tests)
	PathPrefix        string                          // required, e.g. "/auth"; see ValidatePathPrefix
	Routes            []auth.Route                    // provider routes, absolute paths
	Guard             *session.Guard                  // required
	APIKeys           *apikey.Authenticator           // optional; runs before the Guard on the checks
	Signer            *jwt.Signer                     // optional; enables the JWT header and {prefix}/jwks
	JWTHeader         string                          // default "Authorization"; value "Bearer <jwt>"; see ValidateJWTHeader
	IdentityEndpoint  bool                            // mounts {prefix}/me
	Emitter           wideevent.Emitter               // required
	Logger            *slog.Logger                    // required: net/http's own error lines (accept errors, panics outside gin) [LOG-013]
	SampleRate        int                             // required, >= 1: keep every Nth successful event
	MetricsRegistry   *prometheus.Registry            // required; runtime collectors registered by main [MET-002]
	ReadinessCheck    func(ctx context.Context) error // optional (Redis ping)
	ShutdownDelay     time.Duration                   // 0..MaximumShutdownDelay; readiness answers 503 this long before the listeners drain
	TrustedProxies    []string                        // optional; see ValidateTrustedProxies; empty trusts no proxy
}

// Server serves the forward-auth routes and the metrics endpoint. Build it with NewServer and call Run once.
type Server struct {
	options       ServerOptions
	engine        *gin.Engine
	httpServer    *http.Server
	metricsServer *http.Server
	ready         atomic.Bool
	delay         func(time.Duration) // time.Sleep; replaced by in-package tests
}

// NewServer validates options, registers the HTTP metrics on options.MetricsRegistry and builds the
// engine with every route. It does not listen; Run does.
func NewServer(options *ServerOptions) (*Server, error) {
	resolved, err := resolveServerOptions(options)
	if err != nil {
		return nil, err
	}
	metrics, err := newHTTPMetrics(&httpMetricsOptions{registerer: resolved.MetricsRegistry, pathPrefix: resolved.PathPrefix})
	if err != nil {
		return nil, err
	}
	server := &Server{options: resolved, delay: time.Sleep}
	server.ready.Store(true)
	if server.engine, err = server.newEngine(metrics); err != nil {
		return nil, err
	}
	errorLog := slog.NewLogLogger(resolved.Logger.Handler(), slog.LevelError)
	server.httpServer = newHTTPServer(resolved.Port, server.engine, errorLog)
	server.metricsServer = newMetricsServer(resolved.MetricsPort, resolved.MetricsRegistry, errorLog)
	return server, nil
}

// newMetricsServer serves only GET /metrics of registry.
func newMetricsServer(port int, registry *prometheus.Registry, errorLog *log.Logger) *http.Server {
	routes := http.NewServeMux()
	routes.Handle("GET /metrics", promhttp.HandlerFor(registry, promhttp.HandlerOpts{Registry: registry}))
	return newHTTPServer(port, routes, errorLog)
}

// newHTTPServer bounds every phase of a connection, so slow or idle clients cannot hold it [LAY-006, MET-001],
// and the request line with the headers to 64 KiB (net/http answers 431 above): Traefik forwards the
// client's headers, large cookies fit, and net/http's 1 MiB default would let a client push that into
// every always-kept event.
func newHTTPServer(port int, handler http.Handler, errorLog *log.Logger) *http.Server {
	return &http.Server{
		Addr:              ":" + strconv.Itoa(port),
		Handler:           handler,
		MaxHeaderBytes:    maximumHeaderBytes,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
		ErrorLog:          errorLog,
	}
}

func resolveServerOptions(options *ServerOptions) (ServerOptions, error) {
	if options == nil || options.Guard == nil || options.Emitter == nil || options.Logger == nil || options.MetricsRegistry == nil {
		return ServerOptions{}, errors.New("forwardauth server: Guard, Emitter, Logger and MetricsRegistry are required")
	}
	resolved := *options
	resolved.Routes = slices.Clone(options.Routes)
	resolved.TrustedProxies = slices.Clone(options.TrustedProxies)
	if resolved.JWTHeader == "" {
		resolved.JWTHeader = defaultJWTHeader
	}
	var problems []error
	if err := ValidatePathPrefix(resolved.PathPrefix); err != nil {
		problems = append(problems, fmt.Errorf("PathPrefix %w", err))
	}
	if err := ValidateJWTHeader(resolved.JWTHeader); err != nil {
		problems = append(problems, fmt.Errorf("JWTHeader %w", err))
	}
	if err := ValidateTrustedProxies(resolved.TrustedProxies); err != nil {
		problems = append(problems, fmt.Errorf("TrustedProxies: %w", err))
	}
	if !validPort(resolved.Port) || !validPort(resolved.MetricsPort) {
		problems = append(problems, fmt.Errorf("ports %d and %d must be between 0 and %d", resolved.Port, resolved.MetricsPort, MaximumPort))
	}
	if resolved.SampleRate < 1 {
		problems = append(problems, fmt.Errorf("SampleRate %d must be at least 1", resolved.SampleRate))
	}
	if resolved.ShutdownDelay < 0 || resolved.ShutdownDelay > MaximumShutdownDelay {
		problems = append(problems, fmt.Errorf("ShutdownDelay %s must be between 0 and %s", resolved.ShutdownDelay, MaximumShutdownDelay))
	}
	if len(problems) > 0 {
		return ServerOptions{}, fmt.Errorf("forwardauth server: %w", errors.Join(problems...))
	}
	return resolved, nil
}

// ValidatePathPrefix reports why prefix cannot hold the routes: it must pass redirect.IsPathPrefix, so
// it has no gin parameter, wildcard or "." segment.
func ValidatePathPrefix(prefix string) error {
	if !redirect.IsPathPrefix(prefix) {
		return fmt.Errorf("%q must be \"/\"-separated segments of A-Z a-z 0-9 . _ ~ - without a trailing \"/\" and without a \".\" or \"..\" segment", prefix)
	}
	return nil
}

// ValidateJWTHeader reports why name cannot carry the JWT of a check answer: it must be a header name,
// and not one the check answer or net/http sets itself, which would overwrite or drop the token, nor
// Cookie or Host, which Traefik would overwrite in the upstream request.
func ValidateJWTHeader(name string) error {
	if !headerNamePattern.MatchString(name) {
		return fmt.Errorf("%q is not an HTTP header name", name)
	}
	switch http.CanonicalHeaderKey(name) {
	case "Cache-Control", "Set-Cookie", "Connection", "Content-Length", "Transfer-Encoding":
		return fmt.Errorf("%q is set by the check answer itself", name)
	case "Cookie", "Host":
		return fmt.Errorf("%q would replace the upstream request's own header", name)
	}
	return nil
}

// ValidateTrustedProxies reports every entry that is neither an IP address nor a CIDR. Only a request
// whose peer is one of them may name the client in X-Forwarded-For or X-Real-IP; for every other
// request, request.client_ip is the peer address, so a client cannot forge it.
func ValidateTrustedProxies(entries []string) error {
	var problems []error
	for _, entry := range entries {
		if !isAddressOrNetwork(entry) {
			problems = append(problems, fmt.Errorf("%q is neither an IP address nor a CIDR", entry))
		}
	}
	return errors.Join(problems...)
}

func isAddressOrNetwork(entry string) bool {
	if strings.Contains(entry, "/") {
		_, _, err := net.ParseCIDR(entry)
		return err == nil
	}
	return net.ParseIP(entry) != nil
}

func validPort(port int) bool {
	return port >= 0 && port <= MaximumPort
}

// newEngine builds the gin engine: wide event outermost so it records the final status, then the HTTP
// metrics, then the sums of the outbound calls, then the panic recovery, then the routes. A trailing
// "/" is an unmatched route: gin's redirect would answer before the middleware, without event or
// metric, and print the raw query in debug mode [LOG-009]. Routes match the path as sent (UseRawPath),
// so a percent-encoded variant such as /auth/%75i is unmatched: a proxy matching the encoded path must
// not reach a check or the probe it did not route there. The client IP comes from the forwarding headers
// only behind TrustedProxies; gin.New trusts every peer.
func (s *Server) newEngine(metrics *httpMetrics) (*gin.Engine, error) {
	engine := gin.New()
	engine.RedirectTrailingSlash = false
	engine.UseRawPath = true
	if err := engine.SetTrustedProxies(s.options.TrustedProxies); err != nil {
		return nil, fmt.Errorf("forwardauth server: trusted proxies: %w", err)
	}
	engine.Use(
		wideevent.Middleware(
			wideevent.WithEmitter(latestValues(s.options.Emitter)),
			wideevent.WithSampler(sampler(s.options.SampleRate)),
			wideevent.WithPreEnricher(s.recordRequest),
			wideevent.WithSkipPaths(s.path("/health")),
		),
		metrics.middleware,
		recordDependencies,
		recovery,
	)
	engine.NoRoute(routeNotFound)
	s.registerRoutes(engine)
	return engine, nil
}

func (s *Server) registerRoutes(engine *gin.Engine) {
	engine.GET(s.path("/ui"), s.checkChain(s.options.Guard.RequireUI())...)
	engine.GET(s.path("/api"), s.checkChain(s.options.Guard.RequireAPI())...)
	if s.options.Signer != nil {
		engine.GET(s.path("/jwks"), succeeding(s.options.Signer.JWKSHandler()))
	}
	if s.options.IdentityEndpoint {
		engine.GET(s.path("/me"), ginadapter.Middleware(s.options.Guard.RequireAPI()), requireActive, succeeding(auth.IdentityHandler()))
	}
	engine.GET(s.path("/health"), health)
	engine.GET(s.path("/ready"), s.readiness)
	ginadapter.RegisterRoutes(engine, s.options.Routes)
}

// checkChain is the chain of a forward-auth check: API keys (when configured), the Guard variant, the
// refusal of an inactive identity, the JWT (when enabled), the answer.
func (s *Server) checkChain(guard func(http.Handler) http.Handler) []gin.HandlerFunc {
	var chain []gin.HandlerFunc
	if s.options.APIKeys != nil {
		chain = append(chain, ginadapter.Middleware(s.options.APIKeys.Middleware()))
	}
	chain = append(chain, ginadapter.Middleware(guard), requireActive)
	if s.options.Signer != nil {
		chain = append(chain, s.issueToken)
	}
	return append(chain, forward)
}

// requireActive refuses an inactive identity, or one whose impersonator is inactive, with 403, with or without
// JWT: the Guard and the API keys pass any identity they find, and a check answering 200 lets Traefik forward
// the request.
func requireActive(ginContext *gin.Context) {
	if identity := auth.IdentityFrom(ginContext.Request.Context()); identity != nil && identity.Active && identity.Real().Active {
		return
	}
	err := &auth.Error{Kind: auth.ErrForbidden, Reason: auth.ReasonInactive}
	if we := wideevent.FromGin(ginContext); we != nil {
		we.Failure(err)
	}
	auth.WriteError(ginContext.Writer, err)
	ginContext.Abort()
}

// issueToken puts the identity as a bearer token into the JWT header, which Traefik copies into the
// upstream request (authResponseHeaders).
func (s *Server) issueToken(ginContext *gin.Context) {
	we := wideevent.FromGin(ginContext)
	token, err := s.options.Signer.Sign(auth.IdentityFrom(ginContext.Request.Context()))
	if err != nil {
		if we != nil {
			we.Failure(fmt.Errorf("sign the identity token: %w", err))
		}
		auth.WriteError(ginContext.Writer, err)
		ginContext.Abort()
		return
	}
	ginContext.Header(s.options.JWTHeader, bearerPrefix+token)
	if we != nil {
		we.Bool("forward.jwt_issued", true)
	}
}

// forward answers an authenticated check with 200, so Traefik forwards the original request.
func forward(ginContext *gin.Context) {
	ginContext.Header("Cache-Control", "no-store")
	if we := wideevent.FromGin(ginContext); we != nil {
		we.Success()
	}
	ginContext.Status(http.StatusOK)
}

// readiness answers 503 while the server shuts down or when the readiness check (Redis) fails; the
// check's error is recorded on the wide event, which the sampler keeps as a 5xx [LOG-002]. A 503 during
// shutdown is no failure: it is recorded as a success with ready.shutting_down [LOG-011].
func (s *Server) readiness(ginContext *gin.Context) {
	if !s.ready.Load() {
		if we := wideevent.FromGin(ginContext); we != nil {
			we.Success().Bool("ready.shutting_down", true)
		}
		notReady(ginContext)
		return
	}
	if err := s.checkReadiness(ginContext.Request.Context()); err != nil {
		if we := wideevent.FromGin(ginContext); we != nil {
			we.Failure(fmt.Errorf("readiness check: %w", err))
		}
		notReady(ginContext)
		return
	}
	if we := wideevent.FromGin(ginContext); we != nil {
		we.Success()
	}
	httpjson.Write(ginContext.Writer, http.StatusOK, statusResponse{Status: "ok"})
}

func notReady(ginContext *gin.Context) {
	httpjson.Write(ginContext.Writer, http.StatusServiceUnavailable, auth.ErrorResponse{Code: "unavailable", Message: "not ready"})
}

func (s *Server) checkReadiness(ctx context.Context) error {
	if s.options.ReadinessCheck == nil {
		return nil
	}
	checkContext, cancel := context.WithTimeout(ctx, readinessCheckTimeout)
	defer cancel()
	return s.options.ReadinessCheck(checkContext)
}

func (s *Server) path(route string) string {
	return s.options.PathPrefix + route
}

// statusResponse is the body of the health and readiness answers.
type statusResponse struct {
	Status string `json:"status"`
}

func health(ginContext *gin.Context) {
	httpjson.Write(ginContext.Writer, http.StatusOK, statusResponse{Status: "ok"})
}

func routeNotFound(ginContext *gin.Context) {
	if we := wideevent.FromGin(ginContext); we != nil {
		we.Failure(errNoRoute)
	}
	httpjson.Write(ginContext.Writer, http.StatusNotFound, auth.ErrorResponse{Code: "not_found", Message: "not found"})
}

// succeeding serves handler and records the request as a success: behind its chain the handler cannot fail.
func succeeding(handler http.Handler) gin.HandlerFunc {
	return func(ginContext *gin.Context) {
		handler.ServeHTTP(ginContext.Writer, ginContext.Request)
		if we := wideevent.FromGin(ginContext); we != nil {
			we.Success()
		}
	}
}

// recovery turns a panic of a handler into a 500 JSON answer and records it with its stack on the wide
// event, so the connection stays usable and the event explains the failure.
func recovery(ginContext *gin.Context) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			return
		}
		err := fmt.Errorf("panic: %v", recovered)
		if we := wideevent.FromGin(ginContext); we != nil {
			we.Failure(err).Str("panic.stack", string(debug.Stack()))
		}
		if !ginContext.Writer.Written() {
			auth.WriteError(ginContext.Writer, err)
		}
		ginContext.Abort()
	}()
	ginContext.Next()
}

// Run serves until ctx ends, then answers readiness with 503, waits ShutdownDelay so load balancers
// drop the instance, and drains both listeners within 20 s [LAY-003]. A listener that fails to start
// stops the other one and its error is returned. Both listeners have stopped serving when Run returns [CON-006].
func (s *Server) Run(ctx context.Context) error {
	var serving sync.WaitGroup
	defer serving.Wait() // after the shutdown, which ends both serve calls
	serveErrors := make(chan error, 2)
	for _, server := range []*http.Server{s.httpServer, s.metricsServer} {
		serving.Go(func() { serveErrors <- recovering(server.ListenAndServe)() })
	}

	select {
	case err := <-serveErrors:
		return errors.Join(fmt.Errorf("serve: %w", err), s.shutdown(context.WithoutCancel(ctx)))
	case <-ctx.Done():
	}
	s.ready.Store(false)
	s.delay(s.options.ShutdownDelay)
	return s.shutdown(context.WithoutCancel(ctx))
}

// shutdown drains the public listener, then the metrics listener; a listener that does not drain in
// time is closed.
func (s *Server) shutdown(ctx context.Context) error {
	shutdownContext, cancel := context.WithTimeout(ctx, shutdownTimeout)
	defer cancel()
	var problems []error
	for _, server := range []*http.Server{s.httpServer, s.metricsServer} {
		if err := server.Shutdown(shutdownContext); err != nil {
			problems = append(problems, fmt.Errorf("shut down %s: %w", server.Addr, errors.Join(err, server.Close())))
		}
	}
	return errors.Join(problems...)
}

// recovering turns a panic in work into its error [CON-001].
func recovering(work func() error) func() error {
	return func() (err error) {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("panic: %v\n%s", recovered, debug.Stack())
			}
		}()
		return work()
	}
}
