// Package redisbackend implements session.Backend on Redis, so that sessions work across replicas.
//
// It accepts any redis.UniversalClient (a Client, a ClusterClient or a FailoverClient); the caller
// owns the client and closes it. Every key of one session carries the session ID as Redis Cluster
// hash tag, so the Lua scripts that keep Put, Pop and Revoke atomic run on a single slot.
//
// The package never logs and never starts goroutines. Errors of go-redis are reported by message
// only; callers cannot match on them. The Backend is safe for concurrent use.
package redisbackend
