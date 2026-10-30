package prometheusadapter_test

import (
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/require"

	"github.com/govengers/auth"
	"github.com/govengers/auth/prometheusadapter"
)

func TestNewRejectsIncompleteOptions(t *testing.T) {
	testCases := []struct {
		name    string
		options *prometheusadapter.Options
	}{
		{name: "nil options", options: nil},
		{name: "no registerer", options: &prometheusadapter.Options{Namespace: "forwardauth"}},
		{name: "no namespace", options: &prometheusadapter.Options{Registerer: prometheus.NewRegistry()}},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			counter, err := prometheusadapter.New(testCase.options)

			require.Error(t, err)
			require.Nil(t, counter)
		})
	}
}

func TestNewReturnsTheErrorOfADuplicateRegistration(t *testing.T) {
	registry := prometheus.NewRegistry()
	_, err := prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: "forwardauth"})
	require.NoError(t, err)

	_, err = prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: "forwardauth"})

	require.ErrorContains(t, err, "forwardauth_auth_outcomes_total")
	var alreadyRegistered prometheus.AlreadyRegisteredError
	require.False(t, errors.As(err, &alreadyRegistered), "the client_golang error is not part of the API")
}

func TestObserveCountsPerProviderActionAndResult(t *testing.T) {
	registry := prometheus.NewRegistry()
	counter, err := prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: "forwardauth"})
	require.NoError(t, err)

	counter.Observe(t.Context(), auth.Outcome{Provider: "oidc", Action: auth.ActionCallback, Result: auth.ResultSuccess})
	counter.Observe(t.Context(), auth.Outcome{Provider: "oidc", Action: auth.ActionCallback, Result: auth.ResultSuccess})
	counter.Observe(t.Context(), auth.Outcome{Provider: "session", Action: auth.ActionAuthenticate, Result: auth.ResultDenied, Err: auth.ErrUnauthenticated})

	families, err := registry.Gather()
	require.NoError(t, err)
	require.Len(t, families, 1)
	require.Equal(t, "forwardauth_auth_outcomes_total", families[0].GetName())
	values := map[string]float64{}
	for _, metric := range families[0].GetMetric() {
		labels := map[string]string{}
		for _, pair := range metric.GetLabel() {
			labels[pair.GetName()] = pair.GetValue()
		}
		values[labels["provider"]+" "+labels["action"]+" "+labels["result"]] = metric.GetCounter().GetValue()
	}
	require.Equal(t, map[string]float64{
		"oidc callback success":       2,
		"session authenticate denied": 1,
	}, values)
}

func TestObserveDropsAnOutcomeWithAnInvalidLabelValueInsteadOfPanicking(t *testing.T) {
	registry := prometheus.NewRegistry()
	counter, err := prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: "forwardauth"})
	require.NoError(t, err)

	require.NotPanics(t, func() {
		counter.Observe(t.Context(), auth.Outcome{Provider: "\xff", Action: auth.ActionLogin, Result: auth.ResultSuccess})
	})

	require.Zero(t, testutil.CollectAndCount(registry))
}

func TestTheCounterPassesTheMetricLinter(t *testing.T) {
	registry := prometheus.NewRegistry()
	counter, err := prometheusadapter.New(&prometheusadapter.Options{Registerer: registry, Namespace: "forwardauth"})
	require.NoError(t, err)
	counter.Observe(t.Context(), auth.Outcome{Provider: "github", Action: auth.ActionLogin, Result: auth.ResultSuccess})

	problems, err := testutil.GatherAndLint(registry)

	require.NoError(t, err)
	require.Empty(t, problems)
}
