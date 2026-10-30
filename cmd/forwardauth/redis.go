package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/govengers/auth/internal/dependency"
	"github.com/govengers/auth/internal/forwardauth"
	"github.com/govengers/auth/session"
	"github.com/govengers/auth/session/redisbackend"
)

const redisStartupTimeout = 5 * time.Second

// newBackend opens the Redis client when SESSION_REDIS_ENABLED, fails when Redis does not answer
// [RES-007] and records its calls; otherwise it returns the in-memory backend (exactly one replica).
func (s *sessionStore) newBackend(ctx context.Context, configuration *Configuration, dependencies *forwardauth.Dependencies) (session.Backend, error) {
	if !configuration.SessionRedisEnabled {
		return session.NewMemoryBackend(nil)
	}
	client, err := newRedisClient(configuration)
	if err != nil {
		return nil, err
	}
	s.redis = client
	pingContext, cancel := context.WithTimeout(ctx, redisStartupTimeout)
	defer cancel()
	if err := s.redis.Ping(pingContext).Err(); err != nil {
		return nil, errors.Join(dependency.Error(redisPingAction(configuration), err), s.closeRedis())
	}
	backend, err := redisbackend.New(&redisbackend.Options{Client: s.redis, KeyPrefix: configuration.SessionRedisKeyPrefix})
	if err != nil {
		return nil, errors.Join(err, s.closeRedis())
	}
	return dependencies.Backend(backend), nil
}

// redisPingAction names the variable and the endpoint of a failed boot ping, never a credential.
func redisPingAction(configuration *Configuration) string {
	if configuration.SessionRedisSentinelMaster != "" {
		return fmt.Sprintf("SESSION_REDIS_SENTINEL_ADDRESSES: ping Redis master %q through the sentinels at %s",
			configuration.SessionRedisSentinelMaster, strings.Join(configuration.SessionRedisSentinelAddresses, ","))
	}
	return "SESSION_REDIS_ADDRESS: ping Redis at " + configuration.SessionRedisAddress
}

// newRedisClient returns a client of SESSION_REDIS_ADDRESS, or with SESSION_REDIS_SENTINEL_MASTER one of
// the master the sentinels name. It never retries, so a session Pop whose answer was lost is not run
// twice [RES-004], and honours context deadlines, so the 2 s readiness check and a request's own
// deadline bound each command.
func newRedisClient(configuration *Configuration) (*redis.Client, error) {
	tlsConfig, err := redisTLSConfig(configuration)
	if err != nil {
		return nil, err
	}
	if configuration.SessionRedisSentinelMaster != "" {
		return redis.NewFailoverClient(&redis.FailoverOptions{
			MasterName:            configuration.SessionRedisSentinelMaster,
			SentinelAddrs:         configuration.SessionRedisSentinelAddresses,
			SentinelUsername:      configuration.SessionRedisSentinelUsername,
			SentinelPassword:      configuration.SessionRedisSentinelPassword,
			Username:              configuration.SessionRedisUsername,
			Password:              configuration.SessionRedisPassword,
			DB:                    configuration.SessionRedisDatabase,
			MaxRetries:            -1,
			ContextTimeoutEnabled: true,
			TLSConfig:             tlsConfig, // the sentinels' connections too
		}), nil
	}
	return redis.NewClient(&redis.Options{
		Addr:                  configuration.SessionRedisAddress,
		Username:              configuration.SessionRedisUsername,
		Password:              configuration.SessionRedisPassword,
		DB:                    configuration.SessionRedisDatabase,
		MaxRetries:            -1,
		ContextTimeoutEnabled: true,
		TLSConfig:             tlsConfig,
	}), nil
}

// redisTLSConfig returns nil without SESSION_REDIS_TLS_ENABLED. SESSION_REDIS_TLS_CA_FILE replaces the
// system pool: a private Redis has a private CA, and trusting every public CA on top would accept any
// certificate a public CA issued for the host name.
func redisTLSConfig(configuration *Configuration) (*tls.Config, error) {
	if !configuration.SessionRedisTLSEnabled {
		return nil, nil // go-redis dials plain TCP without a TLS configuration
	}
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, ServerName: configuration.SessionRedisTLSServerName}
	var problems []error
	if configuration.SessionRedisTLSCAFile != "" {
		pool, err := certificatePool(configuration.SessionRedisTLSCAFile)
		if err != nil {
			problems = append(problems, fmt.Errorf("SESSION_REDIS_TLS_CA_FILE: %w", err))
		}
		tlsConfig.RootCAs = pool
	}
	certificate, err := clientCertificate(configuration.SessionRedisTLSCertificateFile, configuration.SessionRedisTLSKeyFile)
	if err != nil {
		problems = append(problems, err)
	}
	if certificate != nil {
		tlsConfig.Certificates = []tls.Certificate{*certificate}
	}
	if len(problems) > 0 {
		return nil, errors.Join(problems...)
	}
	return tlsConfig, nil
}

func certificatePool(file string) (*x509.CertPool, error) {
	content, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(content) {
		return nil, fmt.Errorf("%s holds no PEM certificate", file)
	}
	return pool, nil
}

// clientCertificate loads the mTLS certificate; without both files there is none.
func clientCertificate(certificateFile, keyFile string) (*tls.Certificate, error) {
	switch {
	case certificateFile == "" && keyFile == "":
		return nil, nil
	case keyFile == "":
		return nil, errors.New("SESSION_REDIS_TLS_CERTIFICATE_FILE requires SESSION_REDIS_TLS_KEY_FILE")
	case certificateFile == "":
		return nil, errors.New("SESSION_REDIS_TLS_KEY_FILE requires SESSION_REDIS_TLS_CERTIFICATE_FILE")
	}
	certificate, err := tls.LoadX509KeyPair(certificateFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("SESSION_REDIS_TLS_CERTIFICATE_FILE and SESSION_REDIS_TLS_KEY_FILE: %w", err)
	}
	return &certificate, nil
}

// validateRedis checks the Redis values when SESSION_REDIS_ENABLED; while it is false, they are ignored.
func validateRedis(configuration *Configuration) error {
	if !configuration.SessionRedisEnabled {
		return nil
	}
	problems := []error{
		credentialsProblem("SESSION_REDIS_USERNAME", configuration.SessionRedisUsername, "SESSION_REDIS_PASSWORD", configuration.SessionRedisPassword),
		validateRedisTLS(configuration),
	}
	if configuration.SessionRedisSentinelMaster == "" {
		problems = append(problems, validateRedisStandalone(configuration))
	} else {
		problems = append(problems, validateRedisSentinel(configuration))
	}
	return errors.Join(problems...)
}

func validateRedisStandalone(configuration *Configuration) error {
	problems := []error{requireValues("SESSION_REDIS_ENABLED=true without SESSION_REDIS_SENTINEL_MASTER",
		namedValue{"SESSION_REDIS_ADDRESS", configuration.SessionRedisAddress})}
	if configuration.SessionRedisAddress != "" {
		problems = append(problems, addressProblem("SESSION_REDIS_ADDRESS", configuration.SessionRedisAddress))
	}
	for _, sentinelValue := range []namedValue{
		{"SESSION_REDIS_SENTINEL_ADDRESSES", strings.Join(configuration.SessionRedisSentinelAddresses, ",")},
		{"SESSION_REDIS_SENTINEL_USERNAME", configuration.SessionRedisSentinelUsername},
		{"SESSION_REDIS_SENTINEL_PASSWORD", configuration.SessionRedisSentinelPassword},
	} {
		if sentinelValue.value != "" {
			problems = append(problems, fmt.Errorf("%s is set but SESSION_REDIS_SENTINEL_MASTER is empty: nothing would use it", sentinelValue.name))
		}
	}
	return errors.Join(problems...)
}

func validateRedisSentinel(configuration *Configuration) error {
	var problems []error
	if configuration.SessionRedisAddress != "" {
		problems = append(problems, errors.New("SESSION_REDIS_ADDRESS must be empty with SESSION_REDIS_SENTINEL_MASTER: the sentinels name the master"))
	}
	if len(configuration.SessionRedisSentinelAddresses) == 0 {
		problems = append(problems, errors.New("SESSION_REDIS_SENTINEL_ADDRESSES needs at least one host:port when SESSION_REDIS_SENTINEL_MASTER is set"))
	}
	for _, address := range configuration.SessionRedisSentinelAddresses {
		problems = append(problems, addressProblem("SESSION_REDIS_SENTINEL_ADDRESSES", address))
	}
	problems = append(problems, credentialsProblem("SESSION_REDIS_SENTINEL_USERNAME", configuration.SessionRedisSentinelUsername,
		"SESSION_REDIS_SENTINEL_PASSWORD", configuration.SessionRedisSentinelPassword))
	return errors.Join(problems...)
}

// validateRedisTLS loads the TLS files, so an unreadable or invalid one fails the boot with the others.
func validateRedisTLS(configuration *Configuration) error {
	if configuration.SessionRedisTLSEnabled {
		_, err := redisTLSConfig(configuration)
		return err
	}
	var problems []error
	for _, tlsValue := range []namedValue{
		{"SESSION_REDIS_TLS_CA_FILE", configuration.SessionRedisTLSCAFile},
		{"SESSION_REDIS_TLS_SERVER_NAME", configuration.SessionRedisTLSServerName},
		{"SESSION_REDIS_TLS_CERTIFICATE_FILE", configuration.SessionRedisTLSCertificateFile},
		{"SESSION_REDIS_TLS_KEY_FILE", configuration.SessionRedisTLSKeyFile},
	} {
		if tlsValue.value != "" {
			problems = append(problems, fmt.Errorf("%s is set but SESSION_REDIS_TLS_ENABLED=false: the connection would be plain TCP", tlsValue.name))
		}
	}
	return errors.Join(problems...)
}

// credentialsProblem reports a username without a password: go-redis sends no AUTH then, so the
// username would be ignored.
func credentialsProblem(usernameName, username, passwordName, password string) error {
	if username != "" && password == "" {
		return fmt.Errorf("%s requires %s: without a password no AUTH is sent", usernameName, passwordName)
	}
	return nil
}

func addressProblem(name, address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil || host == "" || port == "" {
		return fmt.Errorf("%s %q must be host:port", name, address)
	}
	return nil
}
