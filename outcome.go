package auth

import "context"

// Action names what a provider was asked to do.
type Action string

// The actions providers report.
const (
	ActionLogin              Action = "login" // redirect start (oidc, github) or credential check (password)
	ActionCallback           Action = "callback"
	ActionLogout             Action = "logout"
	ActionFrontChannelLogout Action = "frontchannel_logout"
	ActionRegister           Action = "register"
	ActionTOTPVerify         Action = "totp_verify"
	ActionTOTPStatus         Action = "totp_status" // password GET {prefix}/totp
	ActionTOTPSetup          Action = "totp_setup"
	ActionTOTPEnable         Action = "totp_enable"
	ActionTOTPDisable        Action = "totp_disable"
	ActionRefreshTeams       Action = "refresh_teams"       // github route
	ActionAuthenticate       Action = "authenticate"        // per request: Guard, apikey, jwt verifier
	ActionRefresh            Action = "refresh"             // Guard calling a Refresher
	ActionImpersonationStart Action = "impersonation_start" // session.Impersonator; Identity is the impersonating one on success
	ActionImpersonationStop  Action = "impersonation_stop"
)

// Result is how an action ended.
type Result string

// The results of an action.
const (
	ResultSuccess   Result = "success"
	ResultChallenge Result = "challenge" // password step done, second factor or enrollment pending
	ResultDenied    Result = "denied"    // a refusal (*Error) was answered
	ResultError     Result = "error"     // an internal failure was answered (500)
)

// The fixed provider names (Identity.Provider, Outcome.Provider); an OIDC provider uses its own Name,
// which must not be one of them.
const (
	ProviderPassword = "password"
	ProviderGitHub   = "github"
	ProviderAPIKey   = "apikey"
	ProviderJWT      = "jwt"     // a JWT verifier's outcomes; its identities keep the provider they were signed for
	ProviderSession  = "session" // the Guard's outcomes when it finds no identity
)

// Outcome is one authentication decision. Err is the refusal for denied, the failure for error,
// and a handled failure for a degraded success (e.g. GitHub token revocation failed, legacy hash upgrade failed).
type Outcome struct {
	Provider string // provider instance name; "session" when the Guard finds no identity
	Action   Action
	Result   Result
	Err      error
	Identity *Identity // the identity concerned, nil when unknown
}

// Observer receives outcomes synchronously, at most once per action per request, with the request
// context. It must not block and must be safe for concurrent use. nil Observer options mean no reporting.
type Observer func(ctx context.Context, outcome Outcome)
