package github

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/govengers/auth"
)

// membership is what the configured team lists say about one user's teams.
type membership struct {
	teams   []string // the user's teams found in AllowedTeams, AdminTeams or RelevantTeams; sorted, unique
	allowed bool     // member of an AllowedTeams team
	admin   bool     // member of an AdminTeams team
}

// teamName is the normalized form of a GitHub team, "org/team-slug" in lower case: GitHub treats
// organization logins and team slugs case-insensitively.
func teamName(organization, slug string) string {
	return strings.ToLower(organization + "/" + slug)
}

// parseTeam validates a configured team "org/team-slug" (one "/", both parts non-empty, no spaces or
// control characters) and returns its normalized form.
func parseTeam(raw string) (string, error) {
	organization, slug, found := strings.Cut(raw, "/")
	if !found || organization == "" || slug == "" || strings.Contains(slug, "/") || strings.ContainsFunc(raw, isForbiddenInTeam) {
		return "", fmt.Errorf("team %q is not \"org/team-slug\"", raw)
	}
	return teamName(organization, slug), nil
}

func isForbiddenInTeam(character rune) bool {
	return unicode.IsSpace(character) || !unicode.IsPrint(character)
}

// parseTeams returns the normalized copies of the configured teams of field.
func parseTeams(field string, raw []string) ([]string, error) {
	teams := make([]string, 0, len(raw))
	for _, team := range raw {
		normalized, err := parseTeam(team)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", field, err)
		}
		teams = append(teams, normalized)
	}
	return teams, nil
}

// membershipOf matches the user's normalized teams against the configured lists.
func (p *Provider) membershipOf(userTeams []string) membership {
	var result membership
	for _, team := range userTeams {
		allowed := slices.Contains(p.options.AllowedTeams, team)
		admin := slices.Contains(p.options.AdminTeams, team)
		if allowed || admin || slices.Contains(p.options.RelevantTeams, team) {
			result.teams = append(result.teams, team)
		}
		result.allowed = result.allowed || allowed
		result.admin = result.admin || admin
	}
	slices.Sort(result.teams)
	result.teams = slices.Compact(result.teams)
	return result
}

// newIdentity is the identity of a GitHub user before the team lists are applied.
func newIdentity(account user) *auth.Identity {
	return &auth.Identity{
		Provider: auth.ProviderGitHub,
		Subject:  strconv.FormatInt(account.ID, 10),
		Username: account.Login,
		Name:     account.Name,
		Email:    account.Email,
		Picture:  account.AvatarURL,
		Active:   true,
	}
}

// withMembership returns a copy of identity with Teams replaced and auth.RoleAdmin added or removed
// according to membership; every other field, other roles included, stays.
func withMembership(identity *auth.Identity, userMembership membership) *auth.Identity {
	updated := identity.Clone()
	updated.Teams = slices.Clone(userMembership.teams)
	updated.Roles = slices.DeleteFunc(updated.Roles, func(role string) bool { return role == auth.RoleAdmin })
	if userMembership.admin {
		updated.Roles = append(updated.Roles, auth.RoleAdmin)
	}
	return updated
}

func notAllowed() error {
	return &auth.Error{Kind: auth.ErrForbidden, Reason: "not in an allowed team"}
}
