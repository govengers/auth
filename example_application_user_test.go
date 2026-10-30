package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/google/uuid"

	"github.com/govengers/auth"
)

// User is the application's own user record; UserRepository stands in for its table.
type User struct {
	ID     uuid.UUID
	Name   string
	Active bool
}

type UserRepository map[uuid.UUID]*User

var errUserNotFound = errors.New("user not found")

// ByID returns the user with id.
func (users UserRepository) ByID(_ context.Context, id uuid.UUID) (*User, error) {
	user, found := users[id]
	if !found {
		return nil, errUserNotFound
	}
	return user, nil
}

type userKey struct{}

// WithUser loads the application user of the authenticated identity and refuses inactive users. Mount it
// after the Guard.
func WithUser(users UserRepository) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			identity := auth.IdentityFrom(request.Context())
			if identity == nil {
				auth.WriteError(writer, &auth.Error{Kind: auth.ErrUnauthenticated})
				return
			}
			user, err := users.ByID(request.Context(), identity.UserID)
			if err != nil {
				auth.WriteError(writer, err) // plain errors answer 500
				return
			}
			if !user.Active {
				auth.WriteError(writer, &auth.Error{Kind: auth.ErrForbidden, Reason: "inactive user"})
				return
			}
			next.ServeHTTP(writer, request.WithContext(context.WithValue(request.Context(), userKey{}, user)))
		})
	}
}

// UserFrom returns the user WithUser stored, or nil.
func UserFrom(ctx context.Context) *User {
	user, _ := ctx.Value(userKey{}).(*User)
	return user
}

// provisionHook is the OnLogin hook of an OIDC or GitHub provider: it finds or creates the application
// user and returns a copy of the identity carrying its ID.
func provisionHook(users UserRepository) auth.Hook {
	return func(_ context.Context, identity *auth.Identity) (*auth.Identity, error) {
		provisioned := identity.Clone() // hooks must not mutate their argument
		provisioned.UserID = uuid.NewSHA1(uuid.NameSpaceURL, []byte(identity.Provider+"/"+identity.Subject))
		if _, found := users[provisioned.UserID]; !found {
			users[provisioned.UserID] = &User{ID: provisioned.UserID, Name: identity.Username, Active: true}
		}
		return provisioned, nil
	}
}

// Example_applicationUser replaces go-basicauth's UserTransformer: an OnLogin hook provisions the
// application user, and a middleware after the Guard loads it per request.
func Example_applicationUser() {
	users := UserRepository{}
	identity, err := provisionHook(users)(context.Background(), &auth.Identity{Provider: "keycloak", Subject: "user-1", Username: "ada", Active: true})
	if err != nil {
		fmt.Println(err)
		return
	}
	profile := WithUser(users)(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = fmt.Fprintln(writer, "hello", UserFrom(request.Context()).Name) // the recorder never fails a write
	}))

	for _, active := range []bool{true, false} {
		users[identity.UserID].Active = active
		// the Guard puts the session's identity into the context; WithIdentity stands in for it here
		request := httptest.NewRequestWithContext(auth.WithIdentity(context.Background(), identity), http.MethodGet, "/profile", nil)
		recorder := httptest.NewRecorder()
		profile.ServeHTTP(recorder, request)
		fmt.Print(recorder.Code, " ", recorder.Body.String())
	}
	// Output:
	// 200 hello ada
	// 403 {"code":"forbidden","message":"access denied"}
}
