//go:build e2e

// Package e2e is the binary end-to-end suite: it runs the forwardauth binary that `just test-e2e` builds
// with coverage (E2E_BINARY, GOCOVERDIR) as a subprocess with an explicit environment, against fake
// providers served by this process.
package e2e

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const (
	stopTimeout = 20 * time.Second
	// testEncryptionKey is base64 of 32 bytes: a fixture, not a secret.
	testEncryptionKey = "MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY="
)

func TestMain(m *testing.M) {
	if binary := os.Getenv("E2E_BINARY"); !filepath.IsAbs(binary) {
		fmt.Fprintln(os.Stderr, "E2E_BINARY must be the absolute path of a forwardauth binary built with -cover: run `just test-e2e`")
		os.Exit(1)
	}
	os.Exit(m.Run())
}

// output collects what the process writes; exec copies stdout and stderr from its own goroutines.
type output struct {
	mutex  sync.Mutex
	buffer bytes.Buffer
}

func (o *output) Write(data []byte) (int, error) {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.buffer.Write(data)
}

func (o *output) String() string {
	o.mutex.Lock()
	defer o.mutex.Unlock()
	return o.buffer.String()
}

// newCommand prepares the binary with exactly environment (plus GOCOVERDIR) in an empty working
// directory, so neither the developer's shell nor a .env file leaks in [CFG-005]. When the test ends,
// the process gets SIGTERM, which lets a -cover binary write its coverage data.
func newCommand(t *testing.T, environment map[string]string) (*exec.Cmd, *output) {
	t.Helper()
	command := exec.CommandContext(t.Context(), os.Getenv("E2E_BINARY")) //nolint:gosec // G702: the suite runs the binary `just test-e2e` built
	command.Dir = t.TempDir()
	command.Env = []string{"GOCOVERDIR=" + os.Getenv("GOCOVERDIR")}
	for key, value := range environment {
		command.Env = append(command.Env, key+"="+value)
	}
	command.Cancel = func() error { return command.Process.Signal(syscall.SIGTERM) }
	command.WaitDelay = stopTimeout
	collected := &output{}
	command.Stdout, command.Stderr = collected, collected
	return command, collected
}

// runToExit runs the binary until it exits on its own and returns its exit code and output.
func runToExit(t *testing.T, environment map[string]string) (int, string) {
	t.Helper()
	command, collected := newCommand(t, environment)
	err := command.Run()
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode(), collected.String()
	}
	require.NoError(t, err, collected.String())
	return 0, collected.String()
}
