package github

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
)

func TestParseTeam(t *testing.T) {
	testCases := []struct {
		raw     string
		want    string
		wantErr bool
	}{
		{raw: "acme/developers", want: "acme/developers"},
		{raw: "Acme/Dev-Ops_2", want: "acme/dev-ops_2"},
		{raw: "acme", wantErr: true},
		{raw: "acme/", wantErr: true},
		{raw: "/developers", wantErr: true},
		{raw: "acme/developers/x", wantErr: true},
		{raw: "acme /developers", wantErr: true},
		{raw: "acme/devel\nopers", wantErr: true},
		{raw: "acme/devel\x00opers", wantErr: true},
		{raw: "", wantErr: true},
	}
	for _, testCase := range testCases {
		t.Run(testCase.raw, func(t *testing.T) {
			got, err := parseTeam(testCase.raw)
			if testCase.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, testCase.want, got)
		})
	}
}

// FuzzParseTeam checks the normalization GitHub teams and configured teams share: an accepted team is
// "org/slug" with exactly one "/", lower-case, equal to the name of the GitHub team it configures, and
// accepted again unchanged.
func FuzzParseTeam(f *testing.F) {
	for _, seed := range []struct{ organization, slug string }{
		{"acme", "developers"}, {"Acme", "DEVELOPERS"}, {"", ""}, {"a/b", "c"}, {"org", "with space"}, {"İstanbul", "K"},
	} {
		f.Add(seed.organization, seed.slug)
	}
	f.Fuzz(func(t *testing.T, organization, slug string) {
		normalized, err := parseTeam(organization + "/" + slug)
		if err != nil {
			return
		}
		require.Equal(t, teamName(organization, slug), normalized)
		require.Equal(t, 1, strings.Count(normalized, "/"))
		require.Equal(t, strings.ToLower(normalized), normalized)
		again, err := parseTeam(normalized)
		require.NoError(t, err)
		require.Equal(t, normalized, again)
	})
}

func TestMembershipOf(t *testing.T) {
	provider := &Provider{options: Options{
		AllowedTeams:  []string{"acme/developers", "acme/contractors"},
		AdminTeams:    []string{"acme/admins"},
		RelevantTeams: []string{"acme/ops"},
	}}
	testCases := []struct {
		name      string
		userTeams []string
		want      membership
	}{
		{name: "allowed", userTeams: []string{"acme/developers"}, want: membership{teams: []string{"acme/developers"}, allowed: true}},
		{
			name:      "allowed admin with relevant team, unrelated team dropped",
			userTeams: []string{"acme/ops", "other/team", "acme/developers", "acme/admins"},
			want:      membership{teams: []string{"acme/admins", "acme/developers", "acme/ops"}, allowed: true, admin: true},
		},
		{name: "admin only is not allowed", userTeams: []string{"acme/admins"}, want: membership{teams: []string{"acme/admins"}, admin: true}},
		{name: "relevant only is not allowed", userTeams: []string{"acme/ops"}, want: membership{teams: []string{"acme/ops"}}},
		{name: "duplicates collapse", userTeams: []string{"acme/developers", "acme/developers"}, want: membership{teams: []string{"acme/developers"}, allowed: true}},
		{name: "no teams", userTeams: nil, want: membership{}},
		{name: "unrelated teams only", userTeams: []string{"other/team"}, want: membership{}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			require.Equal(t, testCase.want, provider.membershipOf(testCase.userTeams))
		})
	}
}

func TestWithMembership(t *testing.T) {
	testCases := []struct {
		name      string
		roles     []string
		admin     bool
		wantRoles []string
	}{
		{name: "adds admin", roles: []string{"editor"}, admin: true, wantRoles: []string{"editor", auth.RoleAdmin}},
		{name: "keeps a single admin", roles: []string{auth.RoleAdmin, "editor"}, admin: true, wantRoles: []string{"editor", auth.RoleAdmin}},
		{name: "removes admin, keeps other roles", roles: []string{auth.RoleAdmin, "editor"}, admin: false, wantRoles: []string{"editor"}},
		{name: "no roles", roles: nil, admin: false, wantRoles: nil},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			identity := &auth.Identity{Provider: providerName, Subject: "42", Roles: testCase.roles, Teams: []string{"acme/old"}, Data: map[string]any{"plan": "pro"}}
			before := identity.Clone()
			userMembership := membership{teams: []string{"acme/new"}, allowed: true, admin: testCase.admin}

			updated := withMembership(identity, userMembership)

			require.Equal(t, testCase.wantRoles, updated.Roles)
			require.Equal(t, []string{"acme/new"}, updated.Teams)
			require.Equal(t, map[string]any{"plan": "pro"}, updated.Data)
			require.Equal(t, before, identity)
			userMembership.teams[0] = "changed/later"
			require.Equal(t, []string{"acme/new"}, updated.Teams)
		})
	}
}
