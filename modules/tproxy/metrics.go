package tproxy

import (
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/love4taylor/caddy-tproxy/internal/server"
	"github.com/prometheus/client_golang/prometheus"
)

var latencyBounds = [...]float64{0.001, 0.005, 0.02, 0.05, 0.1, 0.25, 0.5, 1, 3, 5, 10}

type latencyStats struct {
	mu      sync.Mutex
	buckets [len(latencyBounds)]uint64
	count   uint64
	sum     float64
}

func (s *latencyStats) Observe(elapsed time.Duration) {
	seconds := elapsed.Seconds()
	s.mu.Lock()
	s.count++
	s.sum += seconds
	for i, bound := range latencyBounds {
		if seconds <= bound {
			s.buckets[i]++
			break
		}
	}
	s.mu.Unlock()
}

func (s *latencyStats) metric(desc *prometheus.Desc) prometheus.Metric {
	s.mu.Lock()
	defer s.mu.Unlock()
	buckets := make(map[float64]uint64, len(latencyBounds))
	var cumulative uint64
	for i, bound := range latencyBounds {
		cumulative += s.buckets[i]
		buckets[bound] = cumulative
	}
	return prometheus.MustNewConstHistogram(desc, s.count, s.sum, buckets)
}

type backendStats struct {
	handshakesRejected atomic.Uint64
	poolWait           latencyStats
	dialTime           latencyStats
	dials              atomic.Uint64
	dialFailures       atomic.Uint64
	disconnects        atomic.Uint64
	sockets            atomic.Int64
	slowStreams        atomic.Uint64
	writeRejected      atomic.Uint64
	controlOverflows   atomic.Uint64
	writeBatches       atomic.Uint64
	writeFrames        atomic.Uint64
	writeFailures      atomic.Uint64
}

type tproxyMetric struct {
	desc  *prometheus.Desc
	value func() prometheus.Metric
}

type tproxyCollector []tproxyMetric

var metricsInstance atomic.Uint64

func (h *Handler) registerMetrics(registry *prometheus.Registry, relay *server.Server, backend *backend, base string) error {
	// Instances with the same site scope can appear in separate Caddy routes.
	labels := prometheus.Labels{
		"hostname": h.Hostname, "base_path": base,
		"instance": strconv.FormatUint(metricsInstance.Add(1), 10),
	}
	var collector tproxyCollector
	add := func(name, help string, kind prometheus.ValueType, value func() float64) {
		desc := prometheus.NewDesc("caddy_tproxy_"+name, help, nil, labels)
		collector = append(collector, tproxyMetric{desc, func() prometheus.Metric {
			return prometheus.MustNewConstMetric(desc, kind, value())
		}})
	}
	gauge := func(name, help string, value func() int64) {
		add(name, help, prometheus.GaugeValue, func() float64 { return float64(value()) })
	}
	counter := func(name, help string, value func() uint64) {
		add(name, help, prometheus.CounterValue, func() float64 { return float64(value()) })
	}
	histogram := func(name, help string, stats *latencyStats) {
		desc := prometheus.NewDesc("caddy_tproxy_"+name, help, nil, labels)
		collector = append(collector, tproxyMetric{desc, func() prometheus.Metric { return stats.metric(desc) }})
	}

	gauge("sessions", "Active Telegram WEB sessions.", func() int64 { return int64(relay.Capacity().Sessions) })
	gauge("streams", "Active Telegram logical streams.", func() int64 { return int64(relay.Capacity().Streams) })
	gauge("stream_setups", "Logical streams waiting for their first MTProto message.", func() int64 { return int64(relay.Capacity().BackendDialsInFlight) })
	gauge("pending_bytes", "Bytes charged to the shared relay and backend budget.", func() int64 { return int64(relay.Capacity().PendingBytes) })
	gauge("backend_buffer_bytes", "Bytes charged to MTProxy packet and batch buffers.", backend.buffer.used.Load)
	gauge("rpc_connections", "Established Telegram RPC connections.", backend.stats.sockets.Load)
	counter("bytes_up_total", "Telegram WEB carrier bytes received.", func() uint64 { return relay.Metrics().BytesUp })
	counter("bytes_down_total", "Telegram WEB carrier bytes sent.", func() uint64 { return relay.Metrics().BytesDown })
	counter("limit_hits_total", "WEB relay resource limit hits.", func() uint64 { return relay.Metrics().LimitHits })
	counter("stream_setup_failures_total", "Logical streams that failed before their first MTProto message.", func() uint64 { return relay.Metrics().BackendDialFailures })
	counter("rpc_dials_total", "Telegram RPC connection attempts.", backend.stats.dials.Load)
	counter("handshakes_rejected_total", "Obfuscated2 handshakes rejected by the replay window.", backend.stats.handshakesRejected.Load)
	counter("rpc_dial_failures_total", "Telegram RPC connection attempts that failed.", backend.stats.dialFailures.Load)
	counter("rpc_disconnects_total", "Unexpected Telegram RPC disconnections.", backend.stats.disconnects.Load)
	counter("rpc_slow_stream_closes_total", "Logical streams closed when RPC downlink capacity was exhausted.", backend.stats.slowStreams.Load)
	counter("rpc_write_rejections_total", "RPC data frames rejected due to buffer limits.", backend.stats.writeRejected.Load)
	counter("rpc_control_queue_overflows_total", "Required RPC control frames rejected by a full write queue.", backend.stats.controlOverflows.Load)
	counter("rpc_write_failures_total", "RPC socket writes that failed.", backend.stats.writeFailures.Load)
	counter("rpc_write_batches_total", "RPC batches written to Telegram.", backend.stats.writeBatches.Load)
	counter("rpc_write_frames_total", "RPC frames written to Telegram.", backend.stats.writeFrames.Load)
	counter("backend_buffer_rejections_total", "MTProxy buffer reservations denied.", backend.buffer.denied.Load)
	histogram("rpc_dial_seconds", "TCP and Telegram RPC handshake duration.", &backend.stats.dialTime)
	histogram("rpc_pool_wait_seconds", "Time to attach a logical stream to a Telegram RPC connection.", &backend.stats.poolWait)
	if err := registry.Register(collector); err != nil {
		return err
	}
	h.stopMetrics = func() {
		registry.Unregister(collector)
	}
	return nil
}

func (c tproxyCollector) Describe(out chan<- *prometheus.Desc) {
	for _, metric := range c {
		out <- metric.desc
	}
}

func (c tproxyCollector) Collect(out chan<- prometheus.Metric) {
	for _, metric := range c {
		out <- metric.value()
	}
}
