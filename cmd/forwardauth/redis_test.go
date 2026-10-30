package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/stretchr/testify/require"
)

const (
	testRedisUsername    = "forwardauth"
	testRedisPassword    = "redis-password-0123"
	testSentinelUsername = "sentinel-user"
	testSentinelPassword = "sentinel-password-0123"
	testRedisServerName  = "redis.internal"
	testMasterName       = "sessions"
)

// testPKI is a CA with a server certificate for 127.0.0.1 and redis.internal and a client certificate,
// the files a forwardauth configuration names and the server side's TLS configuration.
type testPKI struct {
	caFile, certificateFile, keyFile string
	server                           *tls.Config // requires a client certificate of the CA
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	directory := t.TempDir()
	caKey, caCertificate := newTestCertificate(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "test CA"}, IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign,
	}, nil, nil)
	serverKey, serverCertificate := newTestCertificate(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: testRedisServerName}, DNSNames: []string{testRedisServerName},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}, caCertificate, caKey)
	clientKey, clientCertificate := newTestCertificate(t, &x509.Certificate{
		Subject: pkix.Name{CommonName: "forwardauth"}, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}, caCertificate, caKey)
	pool := x509.NewCertPool()
	pool.AddCert(caCertificate)
	created := &testPKI{
		caFile:          writePEM(t, directory, "ca.pem", "CERTIFICATE", caCertificate.Raw),
		certificateFile: writePEM(t, directory, "client.pem", "CERTIFICATE", clientCertificate.Raw),
		keyFile:         writePEM(t, directory, "client-key.pem", "PRIVATE KEY", marshalKey(t, clientKey)),
		server: &tls.Config{
			MinVersion:   tls.VersionTLS12,
			Certificates: []tls.Certificate{{Certificate: [][]byte{serverCertificate.Raw}, PrivateKey: serverKey}},
			ClientAuth:   tls.RequireAndVerifyClientCert,
			ClientCAs:    pool,
		},
	}
	return created
}

// newTestCertificate signs template with parentKey, or itself without a parent.
func newTestCertificate(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*ecdsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	require.NoError(t, err)
	template.SerialNumber = serial
	template.NotBefore, template.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)
	if parent == nil {
		parent, parentKey = template, key
	}
	raw, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(raw)
	require.NoError(t, err)
	return key, certificate
}

func marshalKey(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	raw, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	return raw
}

func writePEM(t *testing.T, directory, name, blockType string, content []byte) string {
	t.Helper()
	path := filepath.Join(directory, name)
	require.NoError(t, os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: content}), 0o600))
	return path
}

// tlsRedis is a miniredis that serves TLS with pki's server certificate and requires username and password.
func tlsRedis(t *testing.T, pki *testPKI) *miniredis.Miniredis {
	t.Helper()
	server := miniredis.NewMiniRedis()
	require.NoError(t, server.StartTLS(pki.server))
	t.Cleanup(server.Close)
	server.RequireUserAuth(testRedisUsername, testRedisPassword)
	return server
}

func tlsConfiguration(pki *testPKI) *Configuration {
	configuration := validOIDCConfiguration()
	configuration.SessionRedisEnabled = true
	configuration.SessionRedisUsername, configuration.SessionRedisPassword = testRedisUsername, testRedisPassword
	configuration.SessionRedisTLSEnabled = true
	configuration.SessionRedisTLSCAFile = pki.caFile
	configuration.SessionRedisTLSCertificateFile, configuration.SessionRedisTLSKeyFile = pki.certificateFile, pki.keyFile
	return configuration
}

func sentinelConfiguration(pki *testPKI, sentinelAddress string) *Configuration {
	configuration := tlsConfiguration(pki)
	configuration.SessionRedisSentinelMaster = testMasterName
	configuration.SessionRedisSentinelAddresses = []string{sentinelAddress}
	configuration.SessionRedisSentinelUsername, configuration.SessionRedisSentinelPassword = testSentinelUsername, testSentinelPassword
	return configuration
}

func TestValidateConfigurationChecksRedis(t *testing.T) {
	pki := newTestPKI(t)
	garbage := filepath.Join(t.TempDir(), "garbage.pem")
	require.NoError(t, os.WriteFile(garbage, []byte("not a PEM file"), 0o600))
	missing := filepath.Join(t.TempDir(), "missing.pem")
	testCases := []struct {
		name     string
		change   func(configuration *Configuration)
		problems []string // none: the configuration is valid
	}{
		{name: "address with ACL user and mutual TLS", change: func(*Configuration) {}},
		{name: "sentinel with mutual TLS", change: func(configuration *Configuration) {
			*configuration = *sentinelConfiguration(pki, "sentinel-1:26379")
			configuration.SessionRedisSentinelAddresses = append(configuration.SessionRedisSentinelAddresses, "[fd00::1]:26379")
		}},
		{name: "TLS with the system pool and a server name", change: func(configuration *Configuration) {
			configuration.SessionRedisTLSCAFile, configuration.SessionRedisTLSCertificateFile, configuration.SessionRedisTLSKeyFile = "", "", ""
			configuration.SessionRedisTLSServerName = testRedisServerName
		}},
		{name: "values of a disabled Redis are ignored", change: func(configuration *Configuration) {
			configuration.SessionRedisEnabled, configuration.SessionRedisTLSEnabled = false, false
			configuration.SessionRedisAddress, configuration.SessionRedisSentinelMaster = "", testMasterName
		}},
		{
			name: "neither address nor sentinel master", change: func(configuration *Configuration) { configuration.SessionRedisAddress = "" },
			problems: []string{"SESSION_REDIS_ADDRESS is required when SESSION_REDIS_ENABLED=true without SESSION_REDIS_SENTINEL_MASTER"},
		},
		{
			name: "address without port", change: func(configuration *Configuration) { configuration.SessionRedisAddress = "redis" },
			problems: []string{`SESSION_REDIS_ADDRESS "redis" must be host:port`},
		},
		{
			name: "username without password", change: func(configuration *Configuration) { configuration.SessionRedisPassword = "" },
			problems: []string{"SESSION_REDIS_USERNAME requires SESSION_REDIS_PASSWORD"},
		},
		{name: "sentinel values without a master", change: func(configuration *Configuration) {
			configuration.SessionRedisSentinelAddresses = []string{"sentinel-1:26379"}
			configuration.SessionRedisSentinelUsername, configuration.SessionRedisSentinelPassword = testSentinelUsername, testSentinelPassword
		}, problems: []string{
			"SESSION_REDIS_SENTINEL_ADDRESSES is set but SESSION_REDIS_SENTINEL_MASTER is empty",
			"SESSION_REDIS_SENTINEL_USERNAME is set but", "SESSION_REDIS_SENTINEL_PASSWORD is set but",
		}},
		{name: "sentinel master with an address and without sentinels", change: func(configuration *Configuration) {
			configuration.SessionRedisSentinelMaster = testMasterName
			configuration.SessionRedisSentinelUsername = testSentinelUsername
		}, problems: []string{
			"SESSION_REDIS_ADDRESS must be empty with SESSION_REDIS_SENTINEL_MASTER",
			"SESSION_REDIS_SENTINEL_ADDRESSES needs at least one host:port",
			"SESSION_REDIS_SENTINEL_USERNAME requires SESSION_REDIS_SENTINEL_PASSWORD",
		}},
		{name: "sentinel address without port", change: func(configuration *Configuration) {
			*configuration = *sentinelConfiguration(pki, "sentinel-1")
		}, problems: []string{`SESSION_REDIS_SENTINEL_ADDRESSES "sentinel-1" must be host:port`}},
		{name: "TLS values without TLS", change: func(configuration *Configuration) {
			configuration.SessionRedisTLSEnabled, configuration.SessionRedisTLSServerName = false, testRedisServerName
		}, problems: []string{
			"SESSION_REDIS_TLS_CA_FILE is set but SESSION_REDIS_TLS_ENABLED=false", "SESSION_REDIS_TLS_SERVER_NAME is set but",
			"SESSION_REDIS_TLS_CERTIFICATE_FILE is set but", "SESSION_REDIS_TLS_KEY_FILE is set but",
		}},
		{name: "unreadable CA file and certificate without key", change: func(configuration *Configuration) {
			configuration.SessionRedisTLSCAFile, configuration.SessionRedisTLSKeyFile = missing, ""
		}, problems: []string{"SESSION_REDIS_TLS_CA_FILE: open " + missing, "SESSION_REDIS_TLS_CERTIFICATE_FILE requires SESSION_REDIS_TLS_KEY_FILE"}},
		{name: "CA file without certificate and key without certificate", change: func(configuration *Configuration) {
			configuration.SessionRedisTLSCAFile, configuration.SessionRedisTLSCertificateFile = garbage, ""
		}, problems: []string{"SESSION_REDIS_TLS_CA_FILE: " + garbage + " holds no PEM certificate", "SESSION_REDIS_TLS_KEY_FILE requires SESSION_REDIS_TLS_CERTIFICATE_FILE"}},
		{
			name: "key that is no key", change: func(configuration *Configuration) { configuration.SessionRedisTLSKeyFile = garbage },
			problems: []string{"SESSION_REDIS_TLS_CERTIFICATE_FILE and SESSION_REDIS_TLS_KEY_FILE: tls:"},
		},
		{name: "key of another certificate", change: func(configuration *Configuration) {
			configuration.SessionRedisTLSKeyFile = newTestPKI(t).keyFile
		}, problems: []string{"SESSION_REDIS_TLS_CERTIFICATE_FILE and SESSION_REDIS_TLS_KEY_FILE: tls: private key does not match public key"}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configuration := tlsConfiguration(pki)
			configuration.SessionRedisAddress = "redis:6379"
			testCase.change(configuration)

			err := validateConfiguration(configuration)

			if len(testCase.problems) == 0 {
				require.NoError(t, err)
				return
			}
			for _, problem := range testCase.problems {
				require.ErrorContains(t, err, problem)
			}
			for _, secret := range []string{testRedisPassword, testSentinelPassword} {
				require.NotContains(t, err.Error(), secret)
			}
		})
	}
}

func TestNewSessionsReachesRedisOverMutualTLS(t *testing.T) {
	pki := newTestPKI(t)
	redisServer := tlsRedis(t, pki)
	configuration := tlsConfiguration(pki)
	configuration.SessionRedisAddress = redisServer.Addr()

	dependencies := testDependencies(t)
	created, err := newSessionStore(t.Context(), configuration, dependencies)

	require.NoError(t, err)
	t.Cleanup(func() { created.close(slog.New(slog.DiscardHandler)) })
	require.NoError(t, created.readinessCheck(dependencies)(t.Context()))
	require.NoError(t, created.redis.Set(t.Context(), "key", "value", 0).Err())
	value, err := redisServer.Get("key")
	require.NoError(t, err)
	require.Equal(t, "value", value)
}

func TestTheRedisClientVerifiesTheServerAndPresentsItsCertificate(t *testing.T) {
	pki := newTestPKI(t)
	redisServer := tlsRedis(t, pki)
	testCases := []struct {
		name    string
		change  func(configuration *Configuration)
		succeed bool
	}{
		{name: "server name override", change: func(configuration *Configuration) { configuration.SessionRedisTLSServerName = testRedisServerName }, succeed: true},
		{name: "system pool", change: func(configuration *Configuration) { configuration.SessionRedisTLSCAFile = "" }},
		{name: "another CA", change: func(configuration *Configuration) { configuration.SessionRedisTLSCAFile = newTestPKI(t).caFile }},
		{name: "wrong server name", change: func(configuration *Configuration) { configuration.SessionRedisTLSServerName = "other.internal" }},
		{name: "no client certificate", change: func(configuration *Configuration) {
			configuration.SessionRedisTLSCertificateFile, configuration.SessionRedisTLSKeyFile = "", ""
		}},
		{name: "plain TCP", change: func(configuration *Configuration) {
			configuration.SessionRedisTLSEnabled, configuration.SessionRedisTLSCAFile = false, ""
			configuration.SessionRedisTLSCertificateFile, configuration.SessionRedisTLSKeyFile = "", ""
		}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			configuration := tlsConfiguration(pki)
			configuration.SessionRedisAddress = redisServer.Addr()
			testCase.change(configuration)

			created, err := newSessionStore(t.Context(), configuration, testDependencies(t))

			if testCase.succeed {
				require.NoError(t, err)
				created.close(slog.New(slog.DiscardHandler))
				return
			}
			require.ErrorContains(t, err, "SESSION_REDIS_ADDRESS: ping Redis at "+redisServer.Addr())
			require.NotContains(t, err.Error(), testRedisPassword)
		})
	}
}

// sentinelLog records the commands a fake sentinel received.
type sentinelLog struct {
	mutex    sync.Mutex
	commands [][]string
}

func (l *sentinelLog) add(command []string) {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	l.commands = append(l.commands, command)
}

func (l *sentinelLog) received(name string) [][]string {
	l.mutex.Lock()
	defer l.mutex.Unlock()
	var matching [][]string
	for _, command := range l.commands {
		if strings.EqualFold(command[0], name) {
			matching = append(matching, command)
		}
	}
	return matching
}

// fakeSentinel serves TLS with pki's server certificate and answers what go-redis asks a sentinel: it
// refuses HELLO, so the client falls back to RESP2 and AUTH, and names masterAddress as the master.
func fakeSentinel(t *testing.T, pki *testPKI, masterAddress string) (string, *sentinelLog) {
	t.Helper()
	masterHost, masterPort, err := net.SplitHostPort(masterAddress)
	require.NoError(t, err)
	commands := &sentinelLog{}
	address, _ := fakeRedis(t, func(plain net.Conn) {
		connection := tls.Server(plain, pki.server)
		defer func() { _ = connection.Close() }() // the client went away
		reader := bufio.NewReader(connection)
		for {
			command, err := readRESPCommand(reader)
			if err != nil {
				return
			}
			commands.add(command)
			if _, err := io.WriteString(connection, sentinelAnswer(command, masterHost, masterPort)); err != nil {
				return
			}
		}
	})
	return address, commands
}

func sentinelAnswer(command []string, masterHost, masterPort string) string {
	switch strings.ToUpper(strings.Join(command[:min(2, len(command))], " ")) {
	case "SENTINEL GET-MASTER-ADDR-BY-NAME":
		if command[2] != testMasterName {
			return "*-1\r\n"
		}
		return respArray(masterHost, masterPort)
	case "SENTINEL SENTINELS":
		return "*0\r\n"
	}
	switch strings.ToUpper(command[0]) {
	case "HELLO":
		return "-ERR unknown command 'HELLO'\r\n"
	case "PING":
		return "+PONG\r\n"
	case "SUBSCRIBE":
		return "*3\r\n$9\r\nsubscribe\r\n" + respBulk(command[1]) + ":1\r\n"
	default:
		return "+OK\r\n"
	}
}

func respArray(items ...string) string {
	answer := "*" + strconv.Itoa(len(items)) + "\r\n"
	for _, item := range items {
		answer += respBulk(item)
	}
	return answer
}

func respBulk(item string) string {
	return fmt.Sprintf("$%d\r\n%s\r\n", len(item), item)
}

// readRESPCommand reads one command a client sends: an array of bulk strings.
func readRESPCommand(reader *bufio.Reader) ([]string, error) {
	count, err := readRESPLength(reader, '*')
	if err != nil {
		return nil, err
	}
	command := make([]string, count)
	for index := range command {
		length, err := readRESPLength(reader, '$')
		if err != nil {
			return nil, err
		}
		content := make([]byte, length+2) // with the closing \r\n
		if _, err := io.ReadFull(reader, content); err != nil {
			return nil, err
		}
		command[index] = string(content[:length])
	}
	if count == 0 {
		return nil, io.ErrUnexpectedEOF
	}
	return command, nil
}

func readRESPLength(reader *bufio.Reader, prefix byte) (int, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	if line[0] != prefix {
		return 0, fmt.Errorf("RESP line %q does not start with %q", line, prefix)
	}
	return strconv.Atoi(strings.TrimSpace(line[1:]))
}

func TestNewSessionsReachesTheMasterTheSentinelNamesOverTLS(t *testing.T) {
	pki := newTestPKI(t)
	redisServer := tlsRedis(t, pki)
	sentinelAddress, sentinelCommands := fakeSentinel(t, pki, redisServer.Addr())

	dependencies := testDependencies(t)
	created, err := newSessionStore(t.Context(), sentinelConfiguration(pki, sentinelAddress), dependencies)

	require.NoError(t, err)
	t.Cleanup(func() { created.close(slog.New(slog.DiscardHandler)) })
	require.NoError(t, created.readinessCheck(dependencies)(t.Context()))
	require.NoError(t, created.redis.Set(t.Context(), "key", "value", 0).Err())
	value, err := redisServer.Get("key")
	require.NoError(t, err)
	require.Equal(t, "value", value, "the master, reached through the sentinel, with the master's credentials")
	require.Contains(t, sentinelCommands.received("AUTH"), []string{"auth", testSentinelUsername, testSentinelPassword})
	require.NotEmpty(t, sentinelCommands.received("SENTINEL"))
}

func TestNewSessionsNamesTheSentinelsWhenNoneAnswers(t *testing.T) {
	pki := newTestPKI(t)
	address, _ := fakeRedis(t, func(connection net.Conn) { _ = connection.Close() }) // the fake drops the connection on purpose

	created, err := newSessionStore(t.Context(), sentinelConfiguration(pki, address), testDependencies(t))

	require.ErrorContains(t, err, fmt.Sprintf("SESSION_REDIS_SENTINEL_ADDRESSES: ping Redis master %q through the sentinels at %s", testMasterName, address))
	for _, secret := range []string{testRedisPassword, testSentinelPassword} {
		require.NotContains(t, err.Error(), secret)
	}
	require.Nil(t, created)
}
