# Gin

`ginadapter` runs the library's `net/http` middleware in gin chains, registers provider routes on gin, gates routes with checks and records outcomes on the request's wide event of [wide-event-logger](https://github.com/govengers/wide-event-logger) v1. `prometheusadapter` counts outcomes on your Prometheus registry. Only these two packages import gin and client_golang.

## Wiring

From [examples/github/main.go](../../examples/github/main.go) (tested):

```go
	wideEvents, err := wideeventgin.NewMiddleware(&wideeventgin.Options{Emitter: wideevent.NewJSONEmitter(nil)}) // redacts every query value, OAuth code and state included
	if err != nil {
		return nil, err
	}
	// The event records a panic and its stack; gin.Recovery would also print the raw request, cookies included.
	recovery := gin.CustomRecoveryWithWriter(io.Discard, func(ginContext *gin.Context, _ any) {
		ginContext.AbortWithStatus(http.StatusInternalServerError)
	})

	engine := gin.New()
	engine.Use(recovery, wideEvents)
	ginadapter.RegisterRoutes(engine, provider.Routes()) // on the engine root: GET /auth/github/{login,callback,logout}, POST /auth/github/refresh-teams
	engine.GET("/auth/me", ginadapter.Middleware(guard.RequireAPI()), gin.WrapH(auth.IdentityHandler()))
	api := engine.Group("/api", ginadapter.Middleware(guard.RequireAPI()))
	api.GET("/notes", listNotes)
	api.DELETE("/notes", ginadapter.Require(authorization.IsAdmin()), deleteNotes)
	engine.GET("/", ginadapter.Middleware(guard.RequireUI()), home)
```

`wideeventgin` is the logger's own `ginadapter` package (`github.com/govengers/wide-event-logger/ginadapter`), aliased because its name collides with this module's. Handlers read the identity with `auth.IdentityFrom(ginContext.Request.Context())`.

| Function | Use |
|---|---|
| `ginadapter.Middleware(middleware)` | any `func(http.Handler) http.Handler` (Guard, `apikey`, `jwt` verifier, your own) in a gin chain; after it calls next, `c.Request` is the enriched request for later handlers; aborts when it does not call next; wraps once, like a net/http chain, so state the middleware keeps across requests survives |
| `ginadapter.RegisterRoutes(engine, routes)` | provider routes; register on the engine root, route paths are absolute, so gin route templates (and metric labels) are the provider paths |
| `ginadapter.Require(check)` | 401/403/500 JSON when the check refuses; `nil` check answers 500 |
| `ginadapter.RequireMethodPermission(resource)` | GET/HEAD/OPTIONS need `<resource>:read`, every other method `<resource>:write` |
| `ginadapter.Observe` | `auth.Observer` for provider, Guard, `apikey` and verifier options: `auth.*` fields on the wide event |
| `ginadapter.RedactQuery` | deprecated, does nothing: the logger v1 middleware redacts the query itself |

## Wide events

Mount the wide-event-logger v1 middleware (`ginadapter.NewMiddleware` of `github.com/govengers/wide-event-logger`) before every route so `Observe` and `Require` find the event; without one, or with the deprecated `mxcd/go-wide-event-logger`, they record nothing. It records `request.query` with every value replaced by `redacted` unless the parameter is in `Options.QueryAllowlist`, so the `code` and `state` of OAuth callbacks never reach your logs; never allowlist them. `ginadapter.RedactQuery` is a deprecated no-op; drop it from your pre-enricher. Recorded keys: [design 5.4](../design.md#54-wide-event-recording-ginadapterobserve).

## Prometheus

Tested ([prometheusadapter/example_test.go](../../prometheusadapter/example_test.go)):

```go
	registry := prometheus.NewRegistry() // built in main and served on the metrics port
	counter, err := prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: "billing"})
	if err != nil {
		fmt.Println(err)
		return
	}
	var observer auth.Observer = counter.Observe
```

The metric is `<Namespace>_auth_outcomes_total{provider,action,result}`. To feed both the wide event and the counter, pass one `auth.Observer` closure that calls `ginadapter.Observe` and `counter.Observe`.

## Gotchas

- A middleware run through `ginadapter.Middleware` must pass on a request whose context derives from the one it got (`request.WithContext(context.WithValue(request.Context(), ...))`), else 500.
- `IdentityResponse` (and `auth.IdentityHandler`) never expose `Claims`, `Attributes` or `Data`.

Source: [ginadapter/ginadapter.go](../../ginadapter/ginadapter.go), [prometheusadapter/prometheusadapter.go](../../prometheusadapter/prometheusadapter.go).
