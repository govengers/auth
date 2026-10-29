//go:build e2e

package e2e

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/jwt"
)

const (
	startTimeout     = 20 * time.Second
	startAttempts    = 3
	maximumBodyBytes = 1 << 20
)

// instance is one running forwardauth process.
type instance struct {
	baseURL    string // http://127.0.0.1:<PORT>
	metricsURL string // http://127.0.0.1:<METRICS_PORT>
	command    *exec.Cmd
	output     *output
	exited     chan struct{} // closed when the process has exited
}

// start runs the binary on two free ports with environment and waits until {prefix}/health answers.
// EXTERNAL_URL defaults to the instance's own base URL. The process is stopped with SIGTERM when the test
// ends and must then exit with 0. A port that another socket took between freePort and the binary's bind
// is retried on new ports.
func start(t *testing.T, environment map[string]string) *instance {
	t.Helper()
	for attempt := 1; ; attempt++ {
		running := launch(t, environment)
		if running.waitUntilHealthy(t) {
			t.Cleanup(func() { running.requireCleanExit(t) })
			return running
		}
		if attempt == startAttempts || !strings.Contains(running.output.String(), "address already in use") {
			require.FailNow(t, "forwardauth exited during startup", running.output.String())
		}
	}
}

// launch starts the binary on two free ports without waiting for it.
func launch(t *testing.T, environment map[string]string) *instance {
	t.Helper()
	port, metricsPort := freePort(t), freePort(t)
	baseURL := "http://127.0.0.1:" + strconv.Itoa(port)
	withPorts := merged(map[string]string{"PORT": strconv.Itoa(port), "METRICS_PORT": strconv.Itoa(metricsPort), "EXTERNAL_URL": baseURL}, environment)
	command, collected := newCommand(t, withPorts)
	running := &instance{
		baseURL:    baseURL,
		metricsURL: "http://127.0.0.1:" + strconv.Itoa(metricsPort),
		command:    command,
		output:     collected,
		exited:     make(chan struct{}),
	}
	require.NoError(t, command.Start())
	go func() {
		_ = command.Wait() // after the test's SIGTERM it reports the cancelled context; ProcessState tells the exit
		close(running.exited)
	}()
	return running
}

// stop sends SIGTERM, as Kubernetes does, without waiting for the exit.
func (i *instance) stop(t *testing.T) {
	t.Helper()
	require.NoError(t, i.command.Process.Signal(syscall.SIGTERM))
}

func (i *instance) requireCleanExit(t *testing.T) {
	t.Helper()
	if t.Failed() {
		t.Logf("forwardauth output:\n%s", i.output.String())
	}
	_ = i.command.Process.Signal(syscall.SIGTERM) // an exited process cannot be signalled; that is fine
	select {
	case <-i.exited:
	case <-time.After(stopTimeout):
		t.Errorf("forwardauth did not exit within %s after SIGTERM:\n%s", stopTimeout, i.output.String())
		return
	}
	require.True(t, i.command.ProcessState.Success(), "forwardauth did not exit cleanly after SIGTERM (%s):\n%s", i.command.ProcessState, i.output.String())
}

// waitUntilHealthy reports whether {prefix}/health answered before the process exited.
func (i *instance) waitUntilHealthy(t *testing.T) bool {
	t.Helper()
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(startTimeout)
	for time.Now().Before(deadline) {
		select {
		case <-i.exited:
			return false
		default:
		}
		if healthy(t.Context(), client, i.baseURL+"/auth/health") {
			return true
		}
		time.Sleep(50 * time.Millisecond)
	}
	require.FailNow(t, "forwardauth did not become healthy", i.output.String())
	return false
}

func healthy(ctx context.Context, client *http.Client, target string) bool {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return false
	}
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	_ = response.Body.Close() // the status is all we need
	return response.StatusCode == http.StatusOK
}

// freePort asks the kernel for a free loopback port and releases it for the binary; start retries when
// another socket takes it first.
func freePort(t *testing.T) int {
	t.Helper()
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return port
}

// browser is an HTTP client with a cookie jar that never follows a redirect by itself: the test sees
// every hop and asserts on it.
type browser struct {
	t      *testing.T
	client *http.Client
}

// page is one response, fully read.
type page struct {
	status   int
	location string
	header   http.Header
	body     string
}

func newBrowser(t *testing.T) *browser {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return &browser{t: t, client: &http.Client{
		Jar:           jar,
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}}
}

func (b *browser) get(target string, header http.Header) page {
	b.t.Helper()
	return b.do(http.MethodGet, target, header)
}

func (b *browser) do(method, target string, header http.Header) page {
	b.t.Helper()
	request, err := http.NewRequestWithContext(b.t.Context(), method, target, nil)
	require.NoError(b.t, err)
	for name, values := range header {
		request.Header[name] = values
	}
	response, err := b.client.Do(request)
	require.NoError(b.t, err)
	defer func() { _ = response.Body.Close() }() // read-only response
	body, err := io.ReadAll(io.LimitReader(response.Body, maximumBodyBytes))
	require.NoError(b.t, err)
	return page{status: response.StatusCode, location: response.Header.Get("Location"), header: response.Header, body: string(body)}
}

// privateKeyPEM generates the RSA key a JWT-enabled instance signs with.
func privateKeyPEM(t *testing.T) string {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}))
}

// bearerIdentity verifies the "Authorization: Bearer <jwt>" of an answered check against the instance's
// JWKS, as a backend does (flow F15), and returns the identity it carries.
func (i *instance) bearerIdentity(t *testing.T, answer page) *auth.Identity {
	t.Helper()
	token, found := strings.CutPrefix(answer.header.Get("Authorization"), "Bearer ")
	require.True(t, found, "no bearer token in %v", answer.header)
	verifier, err := jwt.NewVerifier(t.Context(), &jwt.VerifierOptions{JWKSURL: i.baseURL + "/auth/jwks", Issuer: i.baseURL})
	require.NoError(t, err)
	identity, err := verifier.Verify(t.Context(), token)
	require.NoError(t, err)
	return identity
}
