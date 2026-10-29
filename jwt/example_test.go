package jwt_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/govengers/auth"
	"github.com/govengers/auth/jwt"
)

// examplePrivateKeyPEM stands in for the PEM key a deployment loads from its secret store.
func examplePrivateKeyPEM() []byte {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})
}

// The forward-auth server signs the identity of every checked request and serves the public key.
func ExampleSigner() {
	signer, err := jwt.NewSigner(&jwt.SignerOptions{PrivateKey: examplePrivateKeyPEM(), Issuer: "https://auth.example.com"})
	if err != nil {
		fmt.Println(err)
		return
	}
	serveMux := http.NewServeMux()
	auth.RegisterRoutes(serveMux, []auth.Route{{Method: http.MethodGet, Path: "/auth/jwks", Handler: signer.JWKSHandler()}})

	token, err := signer.Sign(&auth.Identity{Provider: "github", Subject: "583231", Username: "octocat", Teams: []string{"org/team"}})
	if err != nil {
		fmt.Println(err)
		return
	}
	recorder := httptest.NewRecorder()
	serveMux.ServeHTTP(recorder, httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/auth/jwks", nil))

	fmt.Println(token != "", recorder.Code, recorder.Header().Get("Cache-Control"))
	// Output: true 200 public, max-age=300
}

// A backend verifies the token the forward-auth server put into the Authorization header.
func ExampleVerifier() {
	signer, err := jwt.NewSigner(&jwt.SignerOptions{PrivateKey: examplePrivateKeyPEM(), Issuer: "https://auth.example.com"})
	if err != nil {
		fmt.Println(err)
		return
	}
	forwardAuth := httptest.NewServer(signer.JWKSHandler())
	defer forwardAuth.Close()

	verifier, err := jwt.NewVerifier(context.Background(), &jwt.VerifierOptions{JWKSURL: forwardAuth.URL, Issuer: "https://auth.example.com"})
	if err != nil {
		fmt.Println(err)
		return
	}
	api := verifier.Middleware()(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := auth.IdentityFrom(request.Context())
		fmt.Fprintln(writer, identity.Provider, identity.Username, identity.Teams)
	}))

	token, err := signer.Sign(&auth.Identity{Provider: "github", Subject: "583231", Username: "octocat", Teams: []string{"org/team"}})
	if err != nil {
		fmt.Println(err)
		return
	}
	request := httptest.NewRequestWithContext(context.Background(), http.MethodGet, "/api/items", nil)
	request.Header.Set("Authorization", "Bearer "+token)
	recorder := httptest.NewRecorder()
	api.ServeHTTP(recorder, request)

	fmt.Print(recorder.Code, " ", recorder.Body.String())
	// Output: 200 github octocat [org/team]
}
