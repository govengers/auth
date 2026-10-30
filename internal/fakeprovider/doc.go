// Package fakeprovider holds in-process fakes of the identity providers the library talks to (an OIDC
// issuer with the Keycloak admin API, and GitHub) for unit and end-to-end tests. It is test support:
// excluded from coverage and never imported by library code. Its servers are safe for concurrent use.
package fakeprovider
