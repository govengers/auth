package dependency

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const canary = "alice@example.com"

// thirdPartyError stands for a dependency's own error type.
type thirdPartyError struct{ cause error }

func (e *thirdPartyError) Error() string { return "client: " + e.cause.Error() }

func (e *thirdPartyError) Unwrap() error { return e.cause }

func TestError(t *testing.T) {
	cause := &thirdPartyError{cause: errors.New("connection refused")}

	err := Error("store session value", cause)

	require.EqualError(t, err, "store session value: client: connection refused")
	require.NotErrorIs(t, err, cause, "the dependency's error chain is dropped")
	var dependencyFailure *thirdPartyError
	require.False(t, errors.As(err, &dependencyFailure))
	require.NotErrorIs(t, err, context.Canceled)
	require.NotErrorIs(t, err, context.DeadlineExceeded)
}

func TestErrorKeepsContextErrors(t *testing.T) {
	for _, contextError := range []error{context.Canceled, context.DeadlineExceeded} {
		t.Run(contextError.Error(), func(t *testing.T) {
			cause := &thirdPartyError{cause: contextError}

			err := Error("request admin token", cause)

			require.ErrorIs(t, err, contextError)
			require.EqualError(t, err, "request admin token: client: "+contextError.Error()+": "+contextError.Error())
			var dependencyFailure *thirdPartyError
			require.False(t, errors.As(err, &dependencyFailure), "only the standard library sentinel is wrapped")
		})
	}
}

// An HTTP call's error names neither the URL's path and query nor anything the server sent, also when a
// dependency wrapped it; a cancelled or expired context stays detectable.
func TestErrorReducesAnHTTPCall(t *testing.T) {
	malformed := httptest.NewServer(rawAnswer("HTTP/1.1 200 OK\r\nX-User: " + canary + "\x00\r\n\r\n"))
	t.Cleanup(malformed.Close)
	slow := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
		<-request.Context().Done()
	}))
	t.Cleanup(slow.Close)
	closed := httptest.NewServer(http.NotFoundHandler())
	closed.Close()
	testCases := []struct {
		name      string
		server    string
		cancelled bool
		timeout   time.Duration
		wantText  string
		wantIs    error
	}{
		{name: "malformed answer", server: malformed.URL, wantText: "transport failure ("},
		{name: "connection refused", server: closed.URL, wantText: "dial tcp " + closed.Listener.Addr().String() + ": connect: connection refused"},
		{name: "cancelled", server: slow.URL, cancelled: true, wantText: "context canceled", wantIs: context.Canceled},
		{name: "client timeout", server: slow.URL, timeout: 50 * time.Millisecond, wantText: "context deadline exceeded", wantIs: context.DeadlineExceeded},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			if testCase.cancelled {
				cancel()
			}
			defer cancel()
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, testCase.server+"/teams?login="+canary+"&token=secret-query", nil)
			require.NoError(t, err)
			_, callError := (&http.Client{Timeout: testCase.timeout}).Do(request) //nolint:bodyclose // the call fails, there is no body
			require.ErrorContains(t, callError, canary, "the call's own error repeats the URL")

			for _, cause := range []error{callError, fmt.Errorf("client: get keys %s: %w", request.URL, callError)} {
				err := Error("fetch teams", cause)

				require.ErrorContains(t, err, `fetch teams: Get "`+testCase.server+`": `+testCase.wantText)
				require.NotContains(t, err.Error(), canary)
				require.NotContains(t, err.Error(), "secret")
				require.NotContains(t, err.Error(), "/teams")
				var urlError *url.Error
				require.False(t, errors.As(err, &urlError), "the dependency's chain is dropped")
				if testCase.wantIs != nil {
					require.ErrorIs(t, err, testCase.wantIs)
				}
			}
		})
	}
}

func TestErrorOfAnUnparsableURL(t *testing.T) {
	err := Error("fetch", &url.Error{Op: "parse", URL: "http://a b/%zz?token=secret", Err: url.EscapeError("%zz")})

	require.EqualError(t, err, `fetch: parse "": transport failure (url.EscapeError)`)
}

func TestTransportFailure(t *testing.T) {
	for _, contextError := range []error{context.Canceled, context.DeadlineExceeded} {
		require.ErrorIs(t, TransportFailure(fmt.Errorf("net/http: %w", contextError)), contextError)
	}
	dial := TransportFailure(fmt.Errorf("wrapped: %w", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connect: connection refused")}))
	require.EqualError(t, dial, "dial tcp: connect: connection refused", "a dial error names nothing the server sent")
	var opError *net.OpError
	require.False(t, errors.As(dial, &opError), "no dependency type")
	require.EqualError(t, TransportFailure(&net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded}), "timeout")
	require.EqualError(t, TransportFailure(fmt.Errorf("read: %w", errors.New(canary))), "transport failure (*errors.errorString)")
}

// rawAnswer writes answer as the whole response and closes the connection.
func rawAnswer(answer string) http.HandlerFunc {
	return func(writer http.ResponseWriter, _ *http.Request) {
		connection, _, err := http.NewResponseController(writer).Hijack()
		if err != nil {
			return
		}
		_, _ = connection.Write([]byte(answer)) // the client may already have given up
		_ = connection.Close()                  // nothing to flush
	}
}

func TestWithoutRedirectsSendsNothingToTheRedirectsTarget(t *testing.T) {
	for _, status := range []int{http.StatusFound, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			reached := false
			target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { reached = true }))
			t.Cleanup(target.Close)
			endpoint := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				http.Redirect(writer, request, target.URL+"/token", status)
			}))
			t.Cleanup(endpoint.Close)
			caller := &http.Client{Timeout: time.Second}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint.URL+"/token", strings.NewReader("client_secret="+canary))
			require.NoError(t, err)

			response, err := WithoutRedirects(caller).Do(request)
			if response != nil {
				_ = response.Body.Close() // net/http has closed it already when CheckRedirect fails
			}

			require.Error(t, err)
			require.False(t, reached, "the redirect's target gets no request")
			require.EqualError(t, Error("exchange code", err), `exchange code: Post "`+target.URL+`": redirect refused`)
			require.Nil(t, caller.CheckRedirect, "the caller's client is unchanged")
		})
	}
}
