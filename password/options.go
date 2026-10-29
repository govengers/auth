package password

import (
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/redirect"
	"github.com/govengers/auth/session"
)

const (
	defaultPathPrefix         = "/auth/password"
	defaultMinimumLength      = 12
	defaultPeriod             = 30
	defaultDigits             = 6
	defaultSkew               = 1
	defaultMaximumAttempts    = 5
	defaultPendingTTL         = 5 * time.Minute
	defaultBackupCodeCount    = 10
	defaultBackupCodeLength   = 10
	defaultBackupCodeAlphabet = "0123456789"
	maximumBackupCodeCount    = 20
	minimumBackupCodeSpace    = 1_000_000 // distinct codes, as many as a 6-digit TOTP code has
)

// TOTPOptions configure the second factor.
type TOTPOptions struct {
	Enabled            bool          // routes the TOTP endpoints and challenges users who enabled TOTP
	Required           bool          // users without TOTP enroll during login; needs Enabled
	Issuer             string        // required when Enabled (otpauth issuer)
	Period             uint          // default 30 s
	Digits             uint          // 6 or 8; default 6
	Skew               uint          // periods accepted before and after the current one; default 1
	MaximumAttempts    int           // default 5 wrong codes per password login; must be > 0
	PendingTTL         time.Duration // default 5 min (password step to code step)
	DisableBackupCodes bool
	BackupCodeCount    int    // default 10; at most 20
	BackupCodeLength   int    // default 10; at most 128 bytes per code and at least a million distinct codes
	BackupCodeAlphabet string // default "0123456789"; at least 2 distinct runes, no white space; stored lower-case, repeated runes count once
}

// Options configure New.
type Options struct {
	Sessions             *session.Store // required
	Storage              Storage        // required
	PathPrefix           string         // default "/auth/password"; segments of A-Z a-z 0-9 . _ ~ -, no trailing "/", no "." or ".." segment
	DisableUsernameLogin bool
	DisableEmailLogin    bool // both true: error
	EnableRegistration   bool // off by default: POST {prefix}/register is not even routed
	Policy               Policy
	TOTP                 TOTPOptions
	HashParameters       Parameters                                      // zero value: DefaultParameters(); at least 32 MiB, 1 iteration, salt and key 16 bytes
	LegacyVerifier       func(password, storedHash string) (bool, error) // optional, e.g. VerifyBcrypt; consulted for stored hashes that are not Argon2id
	OnLogin              auth.Hook
	OnLogout             auth.LogoutHook
	Observer             auth.Observer
}

// resolveOptions applies the defaults to options and validates the result.
func resolveOptions(options Options) (Options, error) {
	resolved := withDefaults(options)
	if err := validateOptions(resolved); err != nil {
		return Options{}, fmt.Errorf("password provider: %w", err)
	}
	return resolved, nil
}

func withDefaults(options Options) Options {
	if options.PathPrefix == "" {
		options.PathPrefix = defaultPathPrefix
	}
	if options.Policy.MinimumLength == 0 {
		options.Policy.MinimumLength = defaultMinimumLength
	}
	if options.HashParameters == (Parameters{}) {
		options.HashParameters = DefaultParameters()
	}
	options.TOTP = withTOTPDefaults(options.TOTP)
	return options
}

func withTOTPDefaults(options TOTPOptions) TOTPOptions {
	if options.Period == 0 {
		options.Period = defaultPeriod
	}
	if options.Digits == 0 {
		options.Digits = defaultDigits
	}
	if options.Skew == 0 {
		options.Skew = defaultSkew
	}
	if options.MaximumAttempts == 0 {
		options.MaximumAttempts = defaultMaximumAttempts
	}
	if options.PendingTTL == 0 {
		options.PendingTTL = defaultPendingTTL
	}
	if options.BackupCodeCount == 0 {
		options.BackupCodeCount = defaultBackupCodeCount
	}
	if options.BackupCodeLength == 0 {
		options.BackupCodeLength = defaultBackupCodeLength
	}
	if options.BackupCodeAlphabet == "" {
		options.BackupCodeAlphabet = defaultBackupCodeAlphabet
	}
	options.BackupCodeAlphabet = strings.ToLower(options.BackupCodeAlphabet)
	return options
}

func validateOptions(options Options) error {
	switch {
	case options.Sessions == nil || options.Storage == nil:
		return errors.New("options need Sessions and Storage")
	case !redirect.IsPathPrefix(options.PathPrefix):
		return fmt.Errorf("PathPrefix %q must be a clean path below \"/\" of unreserved URL characters, without a trailing slash", options.PathPrefix)
	case options.DisableUsernameLogin && options.DisableEmailLogin:
		return errors.New("DisableUsernameLogin and DisableEmailLogin leave no way to log in")
	case options.Policy.MinimumLength < 1 || options.Policy.MinimumLength > maximumPasswordLength:
		return fmt.Errorf("Policy.MinimumLength %d is outside 1..%d", options.Policy.MinimumLength, maximumPasswordLength)
	}
	if err := validateCostFloor(options.HashParameters); err != nil {
		return fmt.Errorf("HashParameters: %w", err)
	}
	if err := validateTOTPOptions(options.TOTP); err != nil {
		return fmt.Errorf("TOTP: %w", err)
	}
	return nil
}

func validateTOTPOptions(options TOTPOptions) error {
	if !options.Enabled {
		if options.Required {
			return errors.New("option Required needs Enabled")
		}
		return nil
	}
	switch {
	case options.Issuer == "":
		return errors.New("option Issuer is required")
	case options.Digits != 6 && options.Digits != 8:
		return fmt.Errorf("option Digits %d is neither 6 nor 8", options.Digits)
	case options.MaximumAttempts < 0, options.PendingTTL < 0, options.BackupCodeCount < 0, options.BackupCodeLength < 0:
		return errors.New("MaximumAttempts, PendingTTL, BackupCodeCount and BackupCodeLength must not be negative")
	case options.BackupCodeCount > maximumBackupCodeCount:
		return fmt.Errorf("BackupCodeCount %d is above %d", options.BackupCodeCount, maximumBackupCodeCount)
	}
	return validateBackupCodes(options.BackupCodeAlphabet, options.BackupCodeLength)
}

// validateBackupCodes refuses codes of length characters over alphabet that Hash cannot take or that are too few
// to resist guessing.
func validateBackupCodes(alphabet string, length int) error {
	characters := distinctRunes(alphabet)
	widest := 0
	for _, character := range characters {
		widest = max(widest, utf8.RuneLen(character))
	}
	switch {
	case strings.ContainsFunc(alphabet, unicode.IsSpace):
		return errors.New("BackupCodeAlphabet contains white space")
	case len(characters) < 2:
		return errors.New("BackupCodeAlphabet needs at least 2 distinct characters")
	case length*widest > maximumPasswordLength:
		return fmt.Errorf("BackupCodeLength %d makes codes longer than %d bytes", length, maximumPasswordLength)
	case math.Pow(float64(len(characters)), float64(length)) < minimumBackupCodeSpace:
		return fmt.Errorf("BackupCodeLength %d over %d characters makes fewer than %d codes", length, len(characters), minimumBackupCodeSpace)
	}
	return nil
}

// distinctRunes returns the runes of text, each once.
func distinctRunes(text string) []rune {
	return slices.Compact(slices.Sorted(slices.Values([]rune(text))))
}
