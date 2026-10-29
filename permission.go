package auth

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Access is what a Permission allows on its resource. AccessWrite includes AccessRead.
type Access string

// The closed set of access levels.
const (
	AccessRead  Access = "read"
	AccessWrite Access = "write"
)

// AllResources is the Permission resource that matches every resource.
const AllResources = "*"

// resourcePattern is the charset of a resource name: lower-case, starting with a letter or digit, at most 64 bytes.
var resourcePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// Permission grants Access on one resource, or on every resource when Resource is AllResources. Its
// text form "<resource>:<access>" (e.g. "builds:write", "*:read") is also its JSON form.
type Permission struct {
	Resource string
	Access   Access
}

// ParsePermission parses the text form "<resource>:<access>". Both parts are case-sensitive: the
// resource is AllResources or matches [a-z0-9][a-z0-9._-]{0,63}, the access is "read" or "write".
func ParsePermission(text string) (Permission, error) {
	resource, access, found := strings.Cut(text, ":")
	if !found {
		return Permission{}, fmt.Errorf("permission %q: want <resource>:<access>", text)
	}
	permission := Permission{Resource: resource, Access: Access(access)}
	if err := permission.Validate(); err != nil {
		return Permission{}, err
	}
	return permission, nil
}

// Validate reports whether the permission has a valid resource and access.
func (p Permission) Validate() error {
	if !validResource(p.Resource) {
		return fmt.Errorf("permission %q: resource must be %q or match %s", p.String(), AllResources, resourcePattern)
	}
	if !p.Access.valid() {
		return fmt.Errorf("permission %q: access must be %q or %q", p.String(), AccessRead, AccessWrite)
	}
	return nil
}

// String returns the text form "<resource>:<access>".
func (p Permission) String() string {
	return p.Resource + ":" + string(p.Access)
}

// Allows reports whether the permission grants access on resource: the resource matches exactly or the
// permission covers AllResources, and AccessWrite includes AccessRead. An invalid permission, resource
// or access allows nothing.
func (p Permission) Allows(resource string, access Access) bool {
	if p.Validate() != nil || !validResource(resource) || !access.valid() {
		return false
	}
	if p.Resource != AllResources && p.Resource != resource {
		return false
	}
	return p.Access == AccessWrite || access == AccessRead
}

// MarshalText encodes the text form; an invalid permission is an error.
func (p Permission) MarshalText() ([]byte, error) {
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return []byte(p.String()), nil
}

// UnmarshalText decodes the text form with ParsePermission.
func (p *Permission) UnmarshalText(text []byte) error {
	permission, err := ParsePermission(string(text))
	if err != nil {
		return err
	}
	*p = permission
	return nil
}

// AccessForMethod returns the access an HTTP method needs: AccessRead for GET, HEAD and OPTIONS,
// AccessWrite for every other method.
func AccessForMethod(method string) Access {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return AccessRead
	default:
		return AccessWrite
	}
}

func (a Access) valid() bool {
	return a == AccessRead || a == AccessWrite
}

func validResource(resource string) bool {
	return resource == AllResources || resourcePattern.MatchString(resource)
}
