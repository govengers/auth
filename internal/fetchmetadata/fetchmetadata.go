// Package fetchmetadata reads the Fetch Metadata request headers (Sec-Fetch-*) browsers send. Its
// functions are safe for concurrent use.
package fetchmetadata

import (
	"net/http"

	"github.com/govengers/auth"
)

// RefuseCrossSite refuses a request the browser marks Sec-Fetch-Site: cross-site (a link, form or redirect
// from another site) with *auth.Error ErrForbidden; same-origin, same-site, user-initiated (none) and
// requests without the header (older browsers, non-browser clients) pass with nil.
func RefuseCrossSite(request *http.Request) error {
	if request.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return &auth.Error{Kind: auth.ErrForbidden, Reason: "cross-site request"}
	}
	return nil
}
