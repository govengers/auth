// Command forwardauth is the forward-auth server for Traefik: it authenticates browsers through one
// OIDC or GitHub provider into a server-side session, accepts static API keys, and answers Traefik's
// forwardAuth checks with 200 and, optionally, the identity as a signed JWT for the upstream service.
// It is configured through environment variables only (see Configuration).
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/govengers/config/v2"
	wideevent "github.com/mxcd/go-wide-event-logger"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/redis/go-redis/v9"

	"github.com/govengers/auth"
	"github.com/govengers/auth/apikey"
	"github.com/govengers/auth/github"
	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/internal/forwardauth"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/jwt"
	"github.com/govengers/auth/oidc"
	"github.com/govengers/auth/oidc/keycloak"
	"github.com/govengers/auth/prometheusadapter"
	"github.com/govengers/auth/session"
	"github.com/govengers/auth/session/redisbackend"
)

// version is set at build time with -ldflags "-X main.version=<version>".
var version = "dev"

const (
	providerOIDC   = "oidc"
	providerGitHub = "github"

	claimMapperDefault = "default"
	claimMapperGoogle  = "google"

	grantTypeClientCredentials = "client_credentials"
	grantTypePassword          = "password"

	maximumPort = 65535

	redisStartupTimeout = 5 * time.Second
)

// Configuration holds every value forwardauth reads, filled once at startup.
type Configuration struct {
	Provider                string
	ExternalURL             string
	PathPrefix              string
	Port                    int
	MetricsPort             int
	DevMode                 bool
	WideEventSampleRate     int
	ShutdownDelaySeconds    int
	IdentityEndpointEnabled bool
	APIKeys                 []string
	APIKeyPermissions       []string

	SessionEncryptionKey          string
	SessionCookieName             string
	SessionCookieDomain           string
	SessionInsecureCookie         bool
	SessionSameSite               string
	SessionMaxAgeSeconds          int
	SessionRefreshIntervalSeconds int
	SessionRedisEnabled           bool
	SessionRedisAddress           string
	SessionRedisPassword          string
	SessionRedisDatabase          int
	SessionRedisKeyPrefix         string

	OIDCName                         string
	OIDCIssuer                       string
	OIDCClientID                     string
	OIDCClientSecret                 string
	OIDCScopes                       []string
	OIDCClaimMapper                  string
	OIDCAllowedEmailDomains          []string
	OIDCPostLogoutURL                string
	OIDCDisableIframeLogoutDetection bool

	KeycloakEnabled             bool
	KeycloakURL                 string
	KeycloakRealm               string
	KeycloakAuthenticationRealm string
	KeycloakGrantType           string
	KeycloakClientID            string
	KeycloakClientSecret        string
	KeycloakUsername            string
	KeycloakPassword            string
	KeycloakClientRolesClientID string
	KeycloakRequiredRealmRoles  []string
	KeycloakRequiredClientRoles []string
	KeycloakRequiredGroups      []string

	GitHubClientID      string
	GitHubClientSecret  string
	GitHubScopes        []string
	GitHubAuthorizeURL  string
	GitHubTokenURL      string
	GitHubAPIURL        string
	GitHubAllowedTeams  []string
	GitHubAdminTeams    []string
	GitHubRelevantTeams []string

	JWTEnabled         bool
	JWTPrivateKey      string
	JWTIssuer          string
	JWTAudience        []string
	JWTLifetimeSeconds int
	JWTHeader          string
}

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("forwardauth failed", "error", err.Error())
		os.Exit(1)
	}
}

// run boots in a fixed order [LAY-002]: configuration, metrics registry, session store, provider, Guard,
// API keys, signer, server; then it serves until SIGINT or SIGTERM.
func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	configuration, err := loadConfiguration()
	if err != nil {
		return err
	}
	if err := validateConfiguration(configuration); err != nil {
		return fmt.Errorf("invalid configuration:\n%w", err)
	}
	config.Print()
	gin.SetMode(ginMode(configuration.DevMode)) // process-wide; release mode keeps gin's debug lines off stdout

	sessions, err := newSessions(ctx, configuration)
	if err != nil {
		return err
	}
	defer sessions.close(logger)
	server, err := newServer(ctx, configuration, sessions, logger)
	if err != nil {
		return err
	}
	logger.Info("forwardauth started", "version", version, "provider", configuration.Provider,
		"port", configuration.Port, "metricsPort", configuration.MetricsPort, "redis", configuration.SessionRedisEnabled)
	err = server.Run(ctx)
	logger.Info("forwardauth stopped")
	return err
}

func ginMode(devMode bool) string {
	if devMode {
		return gin.DebugMode
	}
	return gin.ReleaseMode
}

// newServer builds every component after the session store and the server that serves them.
func newServer(ctx context.Context, configuration *Configuration, sessions *sessions, logger *slog.Logger) (*forwardauth.Server, error) {
	metricsRegistry := newMetricsRegistry()
	outcomeCounter, err := prometheusadapter.New(&prometheusadapter.Options{Registerer: metricsRegistry, Namespace: "forwardauth"})
	if err != nil {
		return nil, err
	}
	observer := forwardauth.NewObserver(outcomeCounter)
	selected, err := newProvider(ctx, configuration, sessions.store, observer)
	if err != nil {
		return nil, err
	}
	guard, err := session.NewGuard(&session.GuardOptions{
		Store:            sessions.store,
		LoginURL:         selected.loginURL,
		ReturnPathHeader: "X-Forwarded-Uri",
		Refreshers:       selected.refreshers,
		RefreshInterval:  seconds(configuration.SessionRefreshIntervalSeconds),
		Observer:         observer,
	})
	if err != nil {
		return nil, err
	}
	apiKeys, err := newAPIKeys(configuration, observer)
	if err != nil {
		return nil, err
	}
	signer, err := newSigner(configuration)
	if err != nil {
		return nil, err
	}
	return forwardauth.NewServer(&forwardauth.ServerOptions{
		Version:          version,
		Port:             configuration.Port,
		MetricsPort:      configuration.MetricsPort,
		PathPrefix:       configuration.PathPrefix,
		Routes:           selected.routes,
		Guard:            guard,
		APIKeys:          apiKeys,
		Signer:           signer,
		JWTHeader:        configuration.JWTHeader,
		IdentityEndpoint: configuration.IdentityEndpointEnabled,
		Emitter:          newEmitter(configuration.DevMode),
		Logger:           logger,
		SampleRate:       configuration.WideEventSampleRate,
		MetricsRegistry:  metricsRegistry,
		ReadinessCheck:   sessions.readinessCheck(),
		ShutdownDelay:    seconds(configuration.ShutdownDelaySeconds),
	})
}

// newMetricsRegistry returns the registry /metrics serves, with the Go, process and build-info collectors [MET-002].
func newMetricsRegistry() *prometheus.Registry {
	metricsRegistry := prometheus.NewRegistry()
	metricsRegistry.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		collectors.NewBuildInfoCollector(),
	)
	return metricsRegistry
}

// newEmitter writes wide events as JSON lines on stdout, or readable for a developer in dev mode [LOG-013].
func newEmitter(devMode bool) wideevent.Emitter {
	if devMode {
		return wideevent.DevStdoutEmitter()
	}
	return wideevent.JSONStdoutEmitter()
}

// sessions is the session store and, with SESSION_REDIS_ENABLED, the Redis client behind it.
type sessions struct {
	store *session.Store
	redis *redis.Client // nil for the in-memory backend
}

func newSessions(ctx context.Context, configuration *Configuration) (*sessions, error) {
	encryptionKey, err := session.ParseKey(configuration.SessionEncryptionKey)
	if err != nil {
		return nil, err
	}
	sameSite, err := sameSiteMode(configuration.SessionSameSite)
	if err != nil {
		return nil, err
	}
	created := &sessions{}
	backend, err := created.newBackend(ctx, configuration)
	if err != nil {
		return nil, err
	}
	created.store, err = session.NewStore(&session.StoreOptions{
		Backend:        backend,
		EncryptionKey:  encryptionKey,
		CookieName:     configuration.SessionCookieName,
		CookieDomain:   configuration.SessionCookieDomain,
		SameSite:       sameSite,
		InsecureCookie: configuration.SessionInsecureCookie,
		MaxAge:         seconds(configuration.SessionMaxAgeSeconds),
	})
	if err != nil {
		return nil, errors.Join(err, created.closeRedis())
	}
	return created, nil
}

// newBackend opens the Redis client when SESSION_REDIS_ENABLED and fails when Redis does not answer
// [RES-007]; otherwise it returns the in-memory backend (exactly one replica).
func (s *sessions) newBackend(ctx context.Context, configuration *Configuration) (session.Backend, error) {
	if !configuration.SessionRedisEnabled {
		return session.NewMemoryBackend(nil)
	}
	s.redis = newRedisClient(configuration)
	pingContext, cancel := context.WithTimeout(ctx, redisStartupTimeout)
	defer cancel()
	if err := s.redis.Ping(pingContext).Err(); err != nil {
		return nil, errors.Join(dependency.Error("SESSION_REDIS_ADDRESS: ping Redis at "+configuration.SessionRedisAddress, err), s.closeRedis())
	}
	backend, err := redisbackend.New(&redisbackend.Options{Client: s.redis, KeyPrefix: configuration.SessionRedisKeyPrefix})
	if err != nil {
		return nil, errors.Join(err, s.closeRedis())
	}
	return backend, nil
}

// newRedisClient never retries, so a session Pop whose answer was lost is not run twice [RES-004], and
// honours context deadlines, so the 2 s readiness check and a request's own deadline bound each command.
func newRedisClient(configuration *Configuration) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:                  configuration.SessionRedisAddress,
		Password:              configuration.SessionRedisPassword,
		DB:                    configuration.SessionRedisDatabase,
		MaxRetries:            -1,
		ContextTimeoutEnabled: true,
	})
}

// readinessCheck pings Redis; the in-memory backend needs no check.
func (s *sessions) readinessCheck() func(ctx context.Context) error {
	if s.redis == nil {
		return nil
	}
	return func(ctx context.Context) error { return s.redis.Ping(ctx).Err() }
}

func (s *sessions) closeRedis() error {
	if s.redis == nil {
		return nil
	}
	if err := s.redis.Close(); err != nil {
		return fmt.Errorf("close the Redis client: %w", err)
	}
	return nil
}

// close runs after the server drained; a failure is logged, the process is ending anyway.
func (s *sessions) close(logger *slog.Logger) {
	if err := s.closeRedis(); err != nil {
		logger.Error("shutdown incomplete", "error", err.Error())
	}
}

// selectedProvider is what the Guard and the server need from the configured provider.
type selectedProvider struct {
	routes     []auth.Route
	loginURL   string
	refreshers []session.Refresher
}

// newProvider builds the provider PROVIDER names; its routes live under PATH_PREFIX.
func newProvider(ctx context.Context, configuration *Configuration, store *session.Store, observer auth.Observer) (selectedProvider, error) {
	if configuration.Provider == providerGitHub {
		return newGitHubProvider(configuration, store, observer)
	}
	return newOIDCProvider(ctx, configuration, store, observer)
}

// newOIDCProvider runs the issuer's discovery, so an unreachable issuer fails the boot. With
// KEYCLOAK_ENABLED, the Keycloak Admin API enriches (and may refuse) every login.
func newOIDCProvider(ctx context.Context, configuration *Configuration, store *session.Store, observer auth.Observer) (selectedProvider, error) {
	onLogin, err := newKeycloakHook(configuration)
	if err != nil {
		return selectedProvider{}, err
	}
	provider, err := oidc.New(ctx, &oidc.Options{
		Name:                         configuration.OIDCName,
		Issuer:                       configuration.OIDCIssuer,
		ClientID:                     configuration.OIDCClientID,
		ClientSecret:                 configuration.OIDCClientSecret,
		Scopes:                       configuration.OIDCScopes,
		ExternalURL:                  configuration.ExternalURL,
		PathPrefix:                   configuration.PathPrefix + "/oidc/" + configuration.OIDCName,
		PostLogoutURL:                configuration.OIDCPostLogoutURL,
		ClaimMapper:                  claimMapper(configuration.OIDCClaimMapper),
		AllowedEmailDomains:          configuration.OIDCAllowedEmailDomains,
		DisableIframeLogoutDetection: configuration.OIDCDisableIframeLogoutDetection,
		Sessions:                     store,
		OnLogin:                      onLogin,
		Observer:                     observer,
	})
	if err != nil {
		return selectedProvider{}, err
	}
	return selectedProvider{routes: provider.Routes(), loginURL: provider.LoginURL()}, nil
}

func claimMapper(name string) oidc.ClaimMapper {
	if name == claimMapperGoogle {
		return oidc.GoogleClaimMapper
	}
	return oidc.DefaultClaimMapper
}

// newKeycloakHook returns nil when KEYCLOAK_ENABLED is false: logins then keep the token's roles and groups.
func newKeycloakHook(configuration *Configuration) (auth.Hook, error) {
	if !configuration.KeycloakEnabled {
		return nil, nil // Keycloak disabled is not an error
	}
	client, err := keycloak.New(&keycloak.Options{
		URL:                 configuration.KeycloakURL,
		Realm:               configuration.KeycloakRealm,
		AuthenticationRealm: configuration.KeycloakAuthenticationRealm,
		GrantType:           keycloak.GrantType(configuration.KeycloakGrantType),
		ClientID:            configuration.KeycloakClientID,
		ClientSecret:        configuration.KeycloakClientSecret,
		Username:            configuration.KeycloakUsername,
		Password:            configuration.KeycloakPassword,
		ClientRolesClientID: configuration.KeycloakClientRolesClientID,
		RequiredRealmRoles:  configuration.KeycloakRequiredRealmRoles,
		RequiredClientRoles: configuration.KeycloakRequiredClientRoles,
		RequiredGroups:      configuration.KeycloakRequiredGroups,
	})
	if err != nil {
		return nil, err
	}
	return client.Enrich, nil
}

// newGitHubProvider builds the GitHub provider; it also refreshes the teams of a session every
// SESSION_REFRESH_INTERVAL_SECONDS through the Guard.
func newGitHubProvider(configuration *Configuration, store *session.Store, observer auth.Observer) (selectedProvider, error) {
	provider, err := github.New(&github.Options{
		ClientID:      configuration.GitHubClientID,
		ClientSecret:  configuration.GitHubClientSecret,
		Scopes:        configuration.GitHubScopes,
		AuthorizeURL:  configuration.GitHubAuthorizeURL,
		TokenURL:      configuration.GitHubTokenURL,
		APIURL:        configuration.GitHubAPIURL,
		ExternalURL:   configuration.ExternalURL,
		PathPrefix:    configuration.PathPrefix + "/github",
		AllowedTeams:  configuration.GitHubAllowedTeams,
		AdminTeams:    configuration.GitHubAdminTeams,
		RelevantTeams: configuration.GitHubRelevantTeams,
		Sessions:      store,
		Observer:      observer,
	})
	if err != nil {
		return selectedProvider{}, err
	}
	return selectedProvider{routes: provider.Routes(), loginURL: provider.LoginURL(), refreshers: []session.Refresher{provider}}, nil
}

// newAPIKeys returns nil without API_KEYS: the checks then run without the API key middleware.
func newAPIKeys(configuration *Configuration, observer auth.Observer) (*apikey.Authenticator, error) {
	if len(configuration.APIKeys) == 0 {
		return nil, nil // no keys configured is not an error
	}
	keys, err := apiKeys(configuration.APIKeys, configuration.APIKeyPermissions)
	if err != nil {
		return nil, err
	}
	return apikey.New(&apikey.Options{Keys: keys, Observer: observer})
}

// newSigner returns nil when JWT_ENABLED is false: the checks then answer without a token.
func newSigner(configuration *Configuration) (*jwt.Signer, error) {
	if !configuration.JWTEnabled {
		return nil, nil // JWT disabled is not an error
	}
	issuer := configuration.JWTIssuer
	if issuer == "" {
		issuer = strings.TrimSuffix(configuration.ExternalURL, "/")
	}
	return jwt.NewSigner(&jwt.SignerOptions{
		PrivateKey: []byte(configuration.JWTPrivateKey),
		Issuer:     issuer,
		Audience:   configuration.JWTAudience,
		Lifetime:   seconds(configuration.JWTLifetimeSeconds),
	})
}

func seconds(count int) time.Duration {
	return time.Duration(count) * time.Second
}

// loadConfiguration reads every variable; a missing required one fails the boot with all of them listed.
func loadConfiguration() (*Configuration, error) {
	configuration := &Configuration{}
	err := config.LoadConfig(slices.Concat(
		serverValues(configuration),
		sessionValues(configuration),
		oidcValues(configuration),
		keycloakValues(configuration),
		gitHubValues(configuration),
		jwtValues(configuration),
	))
	if err != nil {
		return nil, fmt.Errorf("load configuration:\n%w", err)
	}
	return configuration, nil
}

func serverValues(configuration *Configuration) []config.Value {
	return []config.Value{
		config.String("PROVIDER").NotEmpty().Into(&configuration.Provider),
		config.String("EXTERNAL_URL").NotEmpty().Into(&configuration.ExternalURL),
		config.String("PATH_PREFIX").NotEmpty().Default("/auth").Into(&configuration.PathPrefix),
		config.Int("PORT").Default(8080).Into(&configuration.Port),
		config.Int("METRICS_PORT").Default(9090).Into(&configuration.MetricsPort),
		config.Bool("DEV_MODE").Default(false).Into(&configuration.DevMode),
		config.Int("WIDE_EVENT_SAMPLE_RATE").Default(10).Into(&configuration.WideEventSampleRate),
		config.Int("SHUTDOWN_DELAY_SECONDS").Default(5).Into(&configuration.ShutdownDelaySeconds),
		config.Bool("IDENTITY_ENDPOINT_ENABLED").Default(false).Into(&configuration.IdentityEndpointEnabled),
		config.StringArray("API_KEYS").Default(nil).Sensitive().Into(&configuration.APIKeys),
		config.StringArray("API_KEY_PERMISSIONS").Default(nil).Into(&configuration.APIKeyPermissions),
	}
}

func sessionValues(configuration *Configuration) []config.Value {
	return []config.Value{
		config.String("SESSION_ENCRYPTION_KEY").NotEmpty().Sensitive().Into(&configuration.SessionEncryptionKey),
		config.String("SESSION_COOKIE_NAME").NotEmpty().Default("forwardauth_session").Into(&configuration.SessionCookieName),
		config.String("SESSION_COOKIE_DOMAIN").Default("").Into(&configuration.SessionCookieDomain),
		config.Bool("SESSION_INSECURE_COOKIE").Default(false).Into(&configuration.SessionInsecureCookie),
		config.String("SESSION_SAME_SITE").NotEmpty().Default("lax").Into(&configuration.SessionSameSite),
		config.Int("SESSION_MAX_AGE_SECONDS").Default(86400).Into(&configuration.SessionMaxAgeSeconds),
		config.Int("SESSION_REFRESH_INTERVAL_SECONDS").Default(60).Into(&configuration.SessionRefreshIntervalSeconds),
		config.Bool("SESSION_REDIS_ENABLED").Default(false).Into(&configuration.SessionRedisEnabled),
		config.String("SESSION_REDIS_ADDRESS").Default("").Into(&configuration.SessionRedisAddress),
		config.String("SESSION_REDIS_PASSWORD").Default("").Sensitive().Into(&configuration.SessionRedisPassword),
		config.Int("SESSION_REDIS_DATABASE").Default(0).Into(&configuration.SessionRedisDatabase),
		config.String("SESSION_REDIS_KEY_PREFIX").NotEmpty().Default("forwardauth").Into(&configuration.SessionRedisKeyPrefix),
	}
}

func oidcValues(configuration *Configuration) []config.Value {
	return []config.Value{
		config.String("OIDC_NAME").NotEmpty().Default("oidc").Into(&configuration.OIDCName),
		config.String("OIDC_ISSUER").Default("").Into(&configuration.OIDCIssuer),
		config.String("OIDC_CLIENT_ID").Default("").Into(&configuration.OIDCClientID),
		config.String("OIDC_CLIENT_SECRET").Default("").Sensitive().Into(&configuration.OIDCClientSecret),
		config.StringArray("OIDC_SCOPES").NotEmpty().Default([]string{"openid", "profile", "email"}).Into(&configuration.OIDCScopes),
		config.String("OIDC_CLAIM_MAPPER").NotEmpty().Default(claimMapperDefault).Into(&configuration.OIDCClaimMapper),
		config.StringArray("OIDC_ALLOWED_EMAIL_DOMAINS").Default(nil).Into(&configuration.OIDCAllowedEmailDomains),
		config.String("OIDC_POST_LOGOUT_URL").Default("").Into(&configuration.OIDCPostLogoutURL),
		config.Bool("OIDC_DISABLE_IFRAME_LOGOUT_DETECTION").Default(false).Into(&configuration.OIDCDisableIframeLogoutDetection),
	}
}

func keycloakValues(configuration *Configuration) []config.Value {
	return []config.Value{
		config.Bool("KEYCLOAK_ENABLED").Default(false).Into(&configuration.KeycloakEnabled),
		config.String("KEYCLOAK_URL").Default("").Into(&configuration.KeycloakURL),
		config.String("KEYCLOAK_REALM").Default("").Into(&configuration.KeycloakRealm),
		config.String("KEYCLOAK_AUTHENTICATION_REALM").Default("").Into(&configuration.KeycloakAuthenticationRealm),
		config.String("KEYCLOAK_GRANT_TYPE").NotEmpty().Default(grantTypeClientCredentials).Into(&configuration.KeycloakGrantType),
		config.String("KEYCLOAK_CLIENT_ID").Default("").Into(&configuration.KeycloakClientID),
		config.String("KEYCLOAK_CLIENT_SECRET").Default("").Sensitive().Into(&configuration.KeycloakClientSecret),
		config.String("KEYCLOAK_USERNAME").Default("").Into(&configuration.KeycloakUsername),
		config.String("KEYCLOAK_PASSWORD").Default("").Sensitive().Into(&configuration.KeycloakPassword),
		config.String("KEYCLOAK_CLIENT_ROLES_CLIENT_ID").Default("").Into(&configuration.KeycloakClientRolesClientID),
		config.StringArray("KEYCLOAK_REQUIRED_REALM_ROLES").Default(nil).Into(&configuration.KeycloakRequiredRealmRoles),
		config.StringArray("KEYCLOAK_REQUIRED_CLIENT_ROLES").Default(nil).Into(&configuration.KeycloakRequiredClientRoles),
		config.StringArray("KEYCLOAK_REQUIRED_GROUPS").Default(nil).Into(&configuration.KeycloakRequiredGroups),
	}
}

func gitHubValues(configuration *Configuration) []config.Value {
	return []config.Value{
		config.String("GITHUB_CLIENT_ID").Default("").Into(&configuration.GitHubClientID),
		config.String("GITHUB_CLIENT_SECRET").Default("").Sensitive().Into(&configuration.GitHubClientSecret),
		config.StringArray("GITHUB_SCOPES").NotEmpty().Default([]string{"read:org"}).Into(&configuration.GitHubScopes),
		config.String("GITHUB_AUTHORIZE_URL").NotEmpty().Default("https://github.com/login/oauth/authorize").Into(&configuration.GitHubAuthorizeURL),
		config.String("GITHUB_TOKEN_URL").NotEmpty().Default("https://github.com/login/oauth/access_token").Into(&configuration.GitHubTokenURL),
		config.String("GITHUB_API_URL").NotEmpty().Default("https://api.github.com").Into(&configuration.GitHubAPIURL),
		config.StringArray("GITHUB_ALLOWED_TEAMS").Default(nil).Into(&configuration.GitHubAllowedTeams),
		config.StringArray("GITHUB_ADMIN_TEAMS").Default(nil).Into(&configuration.GitHubAdminTeams),
		config.StringArray("GITHUB_RELEVANT_TEAMS").Default(nil).Into(&configuration.GitHubRelevantTeams),
	}
}

func jwtValues(configuration *Configuration) []config.Value {
	return []config.Value{
		config.Bool("JWT_ENABLED").Default(false).Into(&configuration.JWTEnabled),
		config.String("JWT_PRIVATE_KEY").Default("").Sensitive().Into(&configuration.JWTPrivateKey),
		config.String("JWT_ISSUER").Default("").Into(&configuration.JWTIssuer),
		config.StringArray("JWT_AUDIENCE").Default(nil).Into(&configuration.JWTAudience),
		config.Int("JWT_LIFETIME_SECONDS").Default(300).Into(&configuration.JWTLifetimeSeconds),
		config.String("JWT_HEADER").NotEmpty().Default("Authorization").Into(&configuration.JWTHeader),
	}
}

// validateConfiguration checks what LoadConfig cannot: formats, ranges and the values a provider or a
// feature requires. It returns every problem at once.
func validateConfiguration(configuration *Configuration) error {
	return errors.Join(
		validateServer(configuration),
		validateSession(configuration),
		validateAPIKeys(configuration),
		validateProvider(configuration),
		validateKeycloak(configuration),
		validateJWT(configuration),
	)
}

func validateServer(configuration *Configuration) error {
	var problems []error
	if _, err := redirect.ExternalURL(configuration.ExternalURL); err != nil {
		problems = append(problems, fmt.Errorf("EXTERNAL_URL: %w", err))
	}
	if !strings.HasPrefix(configuration.PathPrefix, "/") || strings.HasSuffix(configuration.PathPrefix, "/") {
		problems = append(problems, fmt.Errorf("PATH_PREFIX %q must start with \"/\" and must not end with \"/\"", configuration.PathPrefix))
	}
	problems = append(problems,
		rangeProblem("PORT", configuration.Port, 1, maximumPort),
		rangeProblem("METRICS_PORT", configuration.MetricsPort, 1, maximumPort),
		minimumProblem("WIDE_EVENT_SAMPLE_RATE", configuration.WideEventSampleRate, 1),
		rangeProblem("SHUTDOWN_DELAY_SECONDS", configuration.ShutdownDelaySeconds, 0, int(forwardauth.MaximumShutdownDelay/time.Second)),
	)
	if configuration.Port == configuration.MetricsPort {
		problems = append(problems, fmt.Errorf("PORT and METRICS_PORT must differ, both are %d", configuration.Port))
	}
	return errors.Join(problems...)
}

func validateSession(configuration *Configuration) error {
	var problems []error
	if _, err := session.ParseKey(configuration.SessionEncryptionKey); err != nil {
		problems = append(problems, fmt.Errorf("SESSION_ENCRYPTION_KEY: %w", err))
	}
	sameSite, err := sameSiteMode(configuration.SessionSameSite)
	if err != nil {
		problems = append(problems, err)
	}
	if sameSite == http.SameSiteNoneMode && configuration.SessionInsecureCookie {
		problems = append(problems, errors.New("SESSION_SAME_SITE=none requires a secure cookie: unset SESSION_INSECURE_COOKIE"))
	}
	problems = append(problems,
		minimumProblem("SESSION_MAX_AGE_SECONDS", configuration.SessionMaxAgeSeconds, 1),
		minimumProblem("SESSION_REFRESH_INTERVAL_SECONDS", configuration.SessionRefreshIntervalSeconds, 1),
		minimumProblem("SESSION_REDIS_DATABASE", configuration.SessionRedisDatabase, 0),
	)
	if configuration.SessionRedisEnabled {
		problems = append(problems, requireValues("SESSION_REDIS_ENABLED=true", namedValue{"SESSION_REDIS_ADDRESS", configuration.SessionRedisAddress}))
	}
	return errors.Join(problems...)
}

func validateAPIKeys(configuration *Configuration) error {
	_, err := apiKeys(configuration.APIKeys, configuration.APIKeyPermissions)
	return err
}

func validateProvider(configuration *Configuration) error {
	switch configuration.Provider {
	case providerOIDC:
		return validateOIDC(configuration)
	case providerGitHub:
		return validateGitHub(configuration)
	default:
		return fmt.Errorf("PROVIDER %q must be %s or %s", configuration.Provider, providerOIDC, providerGitHub)
	}
}

func validateOIDC(configuration *Configuration) error {
	var problems []error
	problems = append(problems, requireValues("PROVIDER=oidc",
		namedValue{"OIDC_ISSUER", configuration.OIDCIssuer},
		namedValue{"OIDC_CLIENT_ID", configuration.OIDCClientID},
		namedValue{"OIDC_CLIENT_SECRET", configuration.OIDCClientSecret},
	))
	if configuration.OIDCClaimMapper != claimMapperDefault && configuration.OIDCClaimMapper != claimMapperGoogle {
		problems = append(problems, fmt.Errorf("OIDC_CLAIM_MAPPER %q must be %s or %s", configuration.OIDCClaimMapper, claimMapperDefault, claimMapperGoogle))
	}
	return errors.Join(problems...)
}

func validateGitHub(configuration *Configuration) error {
	var problems []error
	problems = append(problems, requireValues("PROVIDER=github",
		namedValue{"GITHUB_CLIENT_ID", configuration.GitHubClientID},
		namedValue{"GITHUB_CLIENT_SECRET", configuration.GitHubClientSecret},
	))
	if len(configuration.GitHubAllowedTeams) == 0 {
		problems = append(problems, errors.New("GITHUB_ALLOWED_TEAMS needs at least one org/team when PROVIDER=github"))
	}
	return errors.Join(problems...)
}

func validateKeycloak(configuration *Configuration) error {
	if !configuration.KeycloakEnabled {
		return nil
	}
	var problems []error
	if configuration.Provider != providerOIDC {
		problems = append(problems, errors.New("KEYCLOAK_ENABLED=true requires PROVIDER=oidc"))
	}
	problems = append(problems, requireValues("KEYCLOAK_ENABLED=true",
		namedValue{"KEYCLOAK_URL", configuration.KeycloakURL},
		namedValue{"KEYCLOAK_REALM", configuration.KeycloakRealm},
	))
	switch configuration.KeycloakGrantType {
	case grantTypeClientCredentials:
		problems = append(problems, requireValues("KEYCLOAK_GRANT_TYPE=client_credentials",
			namedValue{"KEYCLOAK_CLIENT_ID", configuration.KeycloakClientID},
			namedValue{"KEYCLOAK_CLIENT_SECRET", configuration.KeycloakClientSecret},
		))
	case grantTypePassword:
		problems = append(problems, requireValues("KEYCLOAK_GRANT_TYPE=password",
			namedValue{"KEYCLOAK_USERNAME", configuration.KeycloakUsername},
			namedValue{"KEYCLOAK_PASSWORD", configuration.KeycloakPassword},
		))
	default:
		problems = append(problems, fmt.Errorf("KEYCLOAK_GRANT_TYPE %q must be %s or %s", configuration.KeycloakGrantType, grantTypeClientCredentials, grantTypePassword))
	}
	return errors.Join(problems...)
}

func validateJWT(configuration *Configuration) error {
	problems := []error{minimumProblem("JWT_LIFETIME_SECONDS", configuration.JWTLifetimeSeconds, 1)}
	if err := forwardauth.ValidateJWTHeader(configuration.JWTHeader); err != nil {
		problems = append(problems, fmt.Errorf("JWT_HEADER %w", err))
	}
	if configuration.JWTEnabled {
		problems = append(problems, requireValues("JWT_ENABLED=true", namedValue{"JWT_PRIVATE_KEY", configuration.JWTPrivateKey}))
	}
	return errors.Join(problems...)
}

// namedValue is a configuration value with the name of its variable, for problem messages.
type namedValue struct {
	name  string
	value string
}

// requireValues reports every value that is empty although condition makes it required.
func requireValues(condition string, values ...namedValue) error {
	var problems []error
	for _, value := range values {
		if strings.TrimSpace(value.value) == "" {
			problems = append(problems, fmt.Errorf("%s is required when %s", value.name, condition))
		}
	}
	return errors.Join(problems...)
}

func rangeProblem(name string, value, minimum, maximum int) error {
	if value < minimum || value > maximum {
		return fmt.Errorf("%s %d must be between %d and %d", name, value, minimum, maximum)
	}
	return nil
}

func minimumProblem(name string, value, minimum int) error {
	if value < minimum {
		return fmt.Errorf("%s %d must be at least %d", name, value, minimum)
	}
	return nil
}

// sameSiteMode parses SESSION_SAME_SITE.
func sameSiteMode(value string) (http.SameSite, error) {
	switch value {
	case "lax":
		return http.SameSiteLaxMode, nil
	case "strict":
		return http.SameSiteStrictMode, nil
	case "none":
		return http.SameSiteNoneMode, nil
	default:
		return http.SameSiteDefaultMode, fmt.Errorf("SESSION_SAME_SITE %q must be lax, strict or none", value)
	}
}

// apiKeys parses API_KEYS ("name:secret", split at the first ":") and API_KEY_PERMISSIONS
// ("name=permission+permission", split at the first "="). A key without a permissions entry has none.
// Problems name the entry by position and never repeat a secret.
func apiKeys(keyEntries, permissionEntries []string) ([]apikey.Key, error) {
	permissions, problems := keyPermissions(permissionEntries)
	keys := make([]apikey.Key, 0, len(keyEntries))
	for index, entry := range keyEntries {
		name, secret, found := strings.Cut(entry, ":")
		if !found || name == "" {
			problems = append(problems, fmt.Errorf("API_KEYS entry %d must be name:secret with a non-empty name", index+1))
			continue
		}
		keys = append(keys, apikey.Key{Name: name, Secret: secret, Permissions: permissions[name]})
	}
	for _, name := range slices.Sorted(maps.Keys(permissions)) {
		if !slices.ContainsFunc(keys, func(key apikey.Key) bool { return key.Name == name }) {
			problems = append(problems, fmt.Errorf("API_KEY_PERMISSIONS names %q, which is no key in API_KEYS", name))
		}
	}
	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	return keys, nil
}

// keyPermissions parses API_KEY_PERMISSIONS into the permissions per key name.
func keyPermissions(entries []string) (map[string][]auth.Permission, []error) {
	permissions := make(map[string][]auth.Permission, len(entries))
	seen := make(map[string]bool, len(entries))
	var problems []error
	for _, entry := range entries {
		name, list, found := strings.Cut(entry, "=")
		switch {
		case !found || name == "":
			problems = append(problems, fmt.Errorf("API_KEY_PERMISSIONS entry %q must be name=permission[+permission...]", entry))
		case seen[name]:
			problems = append(problems, fmt.Errorf("API_KEY_PERMISSIONS names %q more than once", name))
		case list == "":
			seen[name] = true
			problems = append(problems, fmt.Errorf("API_KEY_PERMISSIONS entry for %q has no permission", name))
		default:
			seen[name] = true
			parsed, err := permissionList(list)
			if err != nil {
				problems = append(problems, fmt.Errorf("API_KEY_PERMISSIONS entry for %q: %w", name, err))
				continue
			}
			permissions[name] = parsed
		}
	}
	return permissions, problems
}

// permissionList parses "<permission>+<permission>...".
func permissionList(list string) ([]auth.Permission, error) {
	var permissions []auth.Permission
	for text := range strings.SplitSeq(list, "+") {
		permission, err := auth.ParsePermission(text)
		if err != nil {
			return nil, err
		}
		permissions = append(permissions, permission)
	}
	return permissions, nil
}
