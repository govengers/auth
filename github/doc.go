// Package github is the GitHub OAuth provider: login with PKCE (S256) and a state bound to the
// server-side session, team checks (AllowedTeams, AdminTeams, RelevantTeams), logout with best-effort
// token revocation, a team refresh route and a session.Refresher, and an HTTP client that calls the
// GitHub API with the session's token.
//
// The OAuth token never leaves the server: it is stored in the session under "github.token". The
// identity in the session carries Provider "github", Subject = the numeric GitHub user ID, Username =
// the login, and Teams = the user's teams that appear in AllowedTeams, AdminTeams or RelevantTeams
// ("org/team-slug", lower-case). Members of an AdminTeams team get auth.RoleAdmin.
//
// Mount Routes on the server, put the Provider into session.GuardOptions.Refreshers so team changes
// reach running sessions within the RefreshInterval, and protect the application with the Guard.
// The package never logs; outcomes go to Options.Observer.
package github
