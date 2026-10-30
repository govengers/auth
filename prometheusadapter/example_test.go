package prometheusadapter_test

import (
	"context"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/govengers/auth"
	"github.com/govengers/auth/prometheusadapter"
)

// The counter's Observe method is an auth.Observer: pass it (or a closure calling it next to
// ginadapter.Observe) as the Observer option of a provider, a session.Guard or an apikey.Authenticator.
func ExampleNew() {
	registry := prometheus.NewRegistry() // built in main and served on the metrics port
	counter, err := prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: "billing"})
	if err != nil {
		fmt.Println(err)
		return
	}
	var observer auth.Observer = counter.Observe

	observer(context.Background(), auth.Outcome{Provider: "session", Action: auth.ActionAuthenticate, Result: auth.ResultSuccess})

	count, err := testutil.GatherAndCount(registry, "billing_auth_outcomes_total")
	fmt.Println(count, err)
	// Output: 1 <nil>
}
