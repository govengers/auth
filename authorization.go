package auth

// Principal represents an authenticated identity and its granted permissions.
type Principal struct {
	Subject     string
	Permissions []string
}

// Authorize reports whether principal has the exact requested permission.
func Authorize(principal Principal, permission string) error {
	if principal.Subject == "" {
		return ErrUnauthenticated
	}
	if permission == "" {
		return ErrPermissionDenied
	}
	for _, granted := range principal.Permissions {
		if granted == permission {
			return nil
		}
	}
	return ErrPermissionDenied
}
