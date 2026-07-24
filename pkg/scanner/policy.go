package scanner

import (
	"time"

	"github.com/hexbay/xmap/pkg/probe"
	"github.com/hexbay/xmap/pkg/types"
)

// tcpProbeScheduler owns service-detection pacing. It deliberately contains no
// I/O: this keeps Nmap-inspired policy (which probe to try and when to stop)
// deterministic and independently testable.
type tcpProbeScheduler struct {
	probes   []*probe.Probe
	next     int
	deadline time.Time
}

func newTCPProbeScheduler(probes []*probe.Probe, options *types.Options) *tcpProbeScheduler {
	timeout := time.Duration(options.Timeout) * time.Second
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// Nmap does not let a silent service consume the sum of every candidate's
	// timeout. The default budget permits a normal banner delay plus one active
	// probe, while --all-probes remains the explicit exhaustive mode.
	budget := time.Duration(options.ServiceProbeBudget) * time.Second
	if budget <= 0 {
		budget = 2 * timeout
	}
	if options.UseAllProbes && options.MaxTimeout > 0 {
		budget = time.Duration(options.MaxTimeout) * time.Second
	}

	return &tcpProbeScheduler{
		probes:   probes,
		deadline: time.Now().Add(budget),
	}
}

func (s *tcpProbeScheduler) nextProbe() (*probe.Probe, bool) {
	if time.Now().After(s.deadline) || s.next >= len(s.probes) {
		return nil, false
	}
	pb := s.probes[s.next]
	s.next++
	return pb, true
}

func (s *tcpProbeScheduler) observe(response []byte, err error) {
	// The scheduler currently uses a time budget as its stop condition. Keep
	// this hook for response-driven expansion (soft matches/fallbacks) and
	// future adaptive retransmission decisions.
	_ = response
	_ = err
}

func (s *tcpProbeScheduler) remaining() time.Duration {
	remaining := time.Until(s.deadline)
	if remaining < 0 {
		return 0
	}
	return remaining
}
