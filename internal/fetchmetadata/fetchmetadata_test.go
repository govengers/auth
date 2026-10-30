package fetchmetadata

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

func TestRefuseCrossSite(t *testing.T) {
	for _, site := range []string{"", "same-origin", "same-site", "none"} {
		t.Run("passes "+site, func(t *testing.T) {
			request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/logout", nil)
			if site != "" {
				request.Header.Set("Sec-Fetch-Site", site)
			}
			require.NoError(t, RefuseCrossSite(request))
		})
	}
	request := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/logout", nil)
	request.Header.Set("Sec-Fetch-Site", "cross-site")

	err := RefuseCrossSite(request)

	status, response := auth.ResponseFor(err)
	require.Equal(t, http.StatusForbidden, status)
	require.Equal(t, "forbidden", response.Code)
}
