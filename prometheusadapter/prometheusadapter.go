// Package prometheusadapter counts authentication outcomes as Prometheus metrics, on a registry the
// caller passes in. It is the only package of the library that imports client_golang: the providers
// report outcomes through an auth.Observer, and OutcomeCounter.Observe is one.
package prometheusadapter

import (
	"context"
	"errors"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/govengers/auth"
	"github.com/govengers/auth/internal/dependency"
)

// Options configure an OutcomeCounter.
type Options struct {
	Registerer prometheus.Registerer // required; the caller's registry, never the default one
	Namespace  string                // required, e.g. "forwardauth"; the metric is <Namespace>_auth_outcomes_total
}

// OutcomeCounter counts authentication outcomes in <namespace>_auth_outcomes_total{provider,action,result}.
// The label values are closed sets: provider instance names, auth.Action and auth.Result. It is safe for
// concurrent use.
type OutcomeCounter struct {
	outcomes *prometheus.CounterVec
}

// New registers <namespace>_auth_outcomes_total on options.Registerer and returns the counter. A failed
// registration (e.g. a duplicate) is returned as an error, never panicked.
func New(options *Options) (*OutcomeCounter, error) {
	if options == nil || options.Registerer == nil {
		return nil, errors.New("prometheusadapter: Registerer is required")
	}
	if options.Namespace == "" {
		return nil, errors.New("prometheusadapter: Namespace is required")
	}
	outcomes := prometheus.NewCounterVec(prometheus.CounterOpts{
		Namespace: options.Namespace,
		Subsystem: "auth",
		Name:      "outcomes_total",
		Help:      "Authentication outcomes by provider, action and result.",
	}, []string{"provider", "action", "result"})
	if err := options.Registerer.Register(outcomes); err != nil {
		return nil, dependency.Error("prometheusadapter: register "+options.Namespace+"_auth_outcomes_total", err)
	}
	return &OutcomeCounter{outcomes: outcomes}, nil
}

// Observe has the auth.Observer shape: it counts outcome under its provider, action and result. An
// outcome with a label value Prometheus refuses (invalid UTF-8) is not counted: an Observer runs inside
// the request and must not panic.
func (c *OutcomeCounter) Observe(_ context.Context, outcome auth.Outcome) {
	counter, err := c.outcomes.GetMetricWithLabelValues(outcome.Provider, string(outcome.Action), string(outcome.Result))
	if err != nil {
		return
	}
	counter.Inc()
}
