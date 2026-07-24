package scanner

import "github.com/hexbay/xmap/pkg/probe"

// ProbePlanner converts a target's transport attributes into an ordered probe
// plan. It has no network side effects, so scheduling policy can be tested
// independently from connection handling and fingerprint matching.
type ProbePlanner struct {
	store      *probe.Store
	exhaustive bool
}

func NewProbePlanner(store *probe.Store, exhaustive bool) ProbePlanner {
	return ProbePlanner{store: store, exhaustive: exhaustive}
}

// Plan implements the high-level selection rule used by Nmap version
// detection: exact-port probes run first, and generic probes are a fallback.
// Exhaustive mode retains generic probes after the exact-port probes.
func (p ProbePlanner) Plan(protocol string, port int, ssl bool) []*probe.Probe {
	probes := p.store.GetProbeForPort(protocol, port, ssl)
	if p.exhaustive {
		probes = p.store.GetAllProbesForPort(protocol, port, ssl)
	}
	preferred := make([]*probe.Probe, 0, len(probes))
	fallback := make([]*probe.Probe, 0, len(probes))
	for _, pb := range probes {
		matchesPort := pb.HasExactPort(port)
		if ssl {
			matchesPort = pb.HasExactSSLPort(port)
		}
		if matchesPort {
			preferred = append(preferred, pb)
		} else {
			fallback = append(fallback, pb)
		}
	}
	if len(preferred) > 0 {
		if p.exhaustive {
			return append(preferred, fallback...)
		}
		return preferred
	}
	return probes
}
