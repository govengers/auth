package password

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/govengers/auth"
)

var (
	usernamePattern = regexp.MustCompile(`^[a-zA-Z0-9_]{3,50}$`)
	emailPattern    = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
)

// Policy is what a password chosen at registration must satisfy.
type Policy struct {
	MinimumLength    int // in characters (runes); default 12; maximum length is fixed at 128 bytes
	RequireUppercase bool
	RequireLowercase bool
	RequireDigit     bool
	RequireSpecial   bool // any rune that is neither letter nor digit
}

// Validate returns the first rule password breaks, nil when password satisfies the policy; a zero MinimumLength
// is the default 12, as in Options. Registration applies the provider's policy itself; check passwords your
// application sets elsewhere (an administrator account, a password change) with the same Policy.
func (p Policy) Validate(password string) error {
	if p.MinimumLength == 0 {
		p.MinimumLength = defaultMinimumLength
	}
	switch {
	case utf8.RuneCountInString(password) < p.MinimumLength:
		return fmt.Errorf("password is shorter than %d characters", p.MinimumLength)
	case len(password) > maximumPasswordLength:
		return fmt.Errorf("password is longer than %d bytes", maximumPasswordLength)
	case p.RequireUppercase && !strings.ContainsFunc(password, unicode.IsUpper):
		return errors.New("password has no upper-case letter")
	case p.RequireLowercase && !strings.ContainsFunc(password, unicode.IsLower):
		return errors.New("password has no lower-case letter")
	case p.RequireDigit && !strings.ContainsFunc(password, unicode.IsDigit):
		return errors.New("password has no digit")
	case p.RequireSpecial && !strings.ContainsFunc(password, isSpecial):
		return errors.New("password has no special character")
	}
	return nil
}

func isSpecial(character rune) bool {
	return !unicode.IsLetter(character) && !unicode.IsDigit(character)
}

// identifierKind is what a login identifier names. The format decides it because the login request has one
// identifier field: usernames cannot contain "@", so an identifier with "@" can only be an email (DES-008
// exception in .govengers.yml).
type identifierKind int

const (
	identifierUsername identifierKind = iota
	identifierEmail
)

func kindOf(identifier string) identifierKind {
	if strings.Contains(identifier, "@") {
		return identifierEmail
	}
	return identifierUsername
}

type registerRequest struct {
	Username *string `json:"username"`
	Email    *string `json:"email"`
	Password string  `json:"password"`
}

// validateRegistration returns the refusal for a registration the options do not allow, or nil.
func validateRegistration(registration registerRequest, options Options) error {
	switch {
	case registration.Username == nil && registration.Email == nil:
		return &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "registration without username and email"}
	case registration.Username != nil && options.DisableUsernameLogin:
		return &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "registration with a username while username login is disabled"}
	case registration.Email != nil && options.DisableEmailLogin:
		return &auth.Error{Kind: auth.ErrInvalidRequest, Reason: "registration with an email while email login is disabled"}
	case registration.Username != nil && !usernamePattern.MatchString(*registration.Username):
		return &auth.Error{Kind: auth.ErrInvalidRequest, Code: codeInvalidUsername, Reason: "username is not 3-50 of [a-zA-Z0-9_]"}
	case registration.Email != nil && !emailPattern.MatchString(*registration.Email):
		return &auth.Error{Kind: auth.ErrInvalidRequest, Code: codeInvalidEmail, Reason: "malformed email"}
	}
	if err := options.Policy.Validate(registration.Password); err != nil {
		return &auth.Error{Kind: auth.ErrInvalidRequest, Code: codeWeakPassword, Reason: err.Error()}
	}
	return nil
}
