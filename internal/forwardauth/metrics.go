package forwardauth

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/prometheus/client_golang/prometheus"
)

const metricsNamespace = "forwardauth"

// httpMetrics records rate, errors and duration of every request except health and readiness [MET-003].
type httpMetrics struct {
	requests      *prometheus.CounterVec
	durations     *prometheus.HistogramVec
	inFlight      prometheus.Gauge
	skippedRoutes map[string]bool
}

func newHTTPMetrics(registerer prometheus.Registerer, pathPrefix string) (*httpMetrics, error) {
	metrics := &httpMetrics{
		requests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Subsystem: "http", Name: "requests_total",
			Help: "HTTP requests by route template, method and status.",
		}, []string{"route", "method", "status"}),
		durations: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace, Subsystem: "http", Name: "request_duration_seconds",
			Help: "HTTP request duration by route template and method.", Buckets: prometheus.DefBuckets,
		}, []string{"route", "method"}),
		inFlight: prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: metricsNamespace, Subsystem: "http", Name: "requests_in_flight",
			Help: "HTTP requests being served.",
		}),
		skippedRoutes: map[string]bool{pathPrefix + "/health": true, pathPrefix + "/ready": true},
	}
	for _, collector := range []prometheus.Collector{metrics.requests, metrics.durations, metrics.inFlight} {
		if err := registerer.Register(collector); err != nil {
			return nil, fmt.Errorf("register the HTTP metrics: %w", err)
		}
	}
	return metrics, nil
}

// middleware records every request under its route template, never under the raw path; requests
// without a matching route count as "unmatched".
func (m *httpMetrics) middleware(ginContext *gin.Context) {
	route := ginContext.FullPath()
	if m.skippedRoutes[route] {
		ginContext.Next()
		return
	}
	if route == "" {
		route = "unmatched"
	}
	start := time.Now()
	m.inFlight.Inc()
	defer m.inFlight.Dec()

	ginContext.Next()

	method := methodLabel(ginContext.Request.Method)
	m.requests.WithLabelValues(route, method, strconv.Itoa(ginContext.Writer.Status())).Inc()
	m.durations.WithLabelValues(route, method).Observe(time.Since(start).Seconds())
}

// methodLabel bounds the method label to the standard methods [MET-004].
func methodLabel(method string) string {
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch,
		http.MethodDelete, http.MethodConnect, http.MethodOptions, http.MethodTrace:
		return method
	default:
		return "other"
	}
}
