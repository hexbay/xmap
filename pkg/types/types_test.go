package types

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestParseTargetSupportsIPv6AndURLs(t *testing.T) {
	target, err := ParseTarget("tcp://[2001:db8::1]:8443")
	if err != nil {
		t.Fatal(err)
	}
	if target.Host != "2001:db8::1" || target.IP != "2001:db8::1" || target.Port != 8443 || target.Protocol != "tcp" {
		t.Fatalf("unexpected IPv6 target: %#v", target)
	}

	target, err = ParseTarget("https://[2001:db8::2]/health")
	if err != nil {
		t.Fatal(err)
	}
	if target.Port != 443 || target.Path != "/health" || target.Scheme != "https" {
		t.Fatalf("unexpected URL target: %#v", target)
	}
}

func TestScanResultJSONUsesStableErrorFields(t *testing.T) {
	result := NewScanResult(NewTarget("127.0.0.1:1"))
	result.Complete(errors.New("not matched"))
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) == "{}" || !strings.Contains(string(data), "error_message") {
		t.Fatalf("missing structured error fields: %s", data)
	}
}

func TestNewTarget(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected *ScanTarget
	}{
		{
			name: "IP with port",
			raw:  "192.168.1.1:8080",
			expected: &ScanTarget{
				Raw:      "192.168.1.1:8080",
				Host:     "192.168.1.1",
				Port:     8080,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "Domain with port",
			raw:  "example.com:8443",
			expected: &ScanTarget{
				Raw:      "example.com:8443",
				Host:     "example.com",
				Port:     8443,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "HTTP URL with domain",
			raw:  "http://example.com",
			expected: &ScanTarget{
				Raw:      "http://example.com",
				Scheme:   "http",
				Host:     "example.com",
				Port:     80,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "HTTPS URL with domain and port",
			raw:  "https://example.com:8443",
			expected: &ScanTarget{
				Raw:      "https://example.com:8443",
				Scheme:   "https",
				Host:     "example.com",
				Port:     8443,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "HTTP URL with IP",
			raw:  "http://192.168.1.1",
			expected: &ScanTarget{
				Raw:      "http://192.168.1.1",
				Scheme:   "http",
				Host:     "192.168.1.1",
				Port:     80,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "HTTPS URL with IP and port",
			raw:  "https://192.168.1.1:8443",
			expected: &ScanTarget{
				Raw:      "https://192.168.1.1:8443",
				Scheme:   "https",
				Host:     "192.168.1.1",
				Port:     8443,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "TCP protocol with domain and port",
			raw:  "tcp://example.com:22",
			expected: &ScanTarget{
				Raw:      "tcp://example.com:22",
				Host:     "example.com",
				Port:     22,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "UDP protocol with domain and port",
			raw:  "udp://example.com:53",
			expected: &ScanTarget{
				Raw:      "udp://example.com:53",
				Host:     "example.com",
				Port:     53,
				Protocol: "udp",
				Parsed:   true,
			},
		},
		{
			name: "HTTP URL with path",
			raw:  "http://example.com/path/to/resource",
			expected: &ScanTarget{
				Raw:      "http://example.com/path/to/resource",
				Scheme:   "http",
				Host:     "example.com",
				Port:     80,
				Protocol: "tcp",
				Path:     "/path/to/resource",
				Parsed:   true,
			},
		},
		{
			name: "HTTPS URL with path and port",
			raw:  "https://example.com:8443/api/v1",
			expected: &ScanTarget{
				Raw:      "https://example.com:8443/api/v1",
				Scheme:   "https",
				Host:     "example.com",
				Port:     8443,
				Protocol: "tcp",
				Path:     "/api/v1",
				Parsed:   true,
			},
		},
		{
			name: "Invalid port",
			raw:  "example.com:invalid",
			expected: &ScanTarget{
				Raw:      "example.com:invalid",
				Host:     "example.com",
				Port:     80,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "Only domain",
			raw:  "example.com",
			expected: &ScanTarget{
				Raw:      "example.com",
				Host:     "example.com",
				Port:     80,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "Only IP",
			raw:  "192.168.1.1",
			expected: &ScanTarget{
				Raw:      "192.168.1.1",
				Host:     "192.168.1.1",
				Port:     80,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
		{
			name: "HTTPS default port",
			raw:  "https://example.com",
			expected: &ScanTarget{
				Raw:      "https://example.com",
				Scheme:   "https",
				Host:     "example.com",
				Port:     443,
				Protocol: "tcp",
				Parsed:   true,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := NewTarget(tt.raw)

			if got.Raw != tt.expected.Raw {
				t.Errorf("Raw = %v, want %v", got.Raw, tt.expected.Raw)
			}
			if got.Scheme != tt.expected.Scheme {
				t.Errorf("Scheme = %v, want %v", got.Scheme, tt.expected.Scheme)
			}
			if got.Host != tt.expected.Host {
				t.Errorf("Host = %v, want %v", got.Host, tt.expected.Host)
			}
			if got.Port != tt.expected.Port {
				t.Errorf("Port = %v, want %v", got.Port, tt.expected.Port)
			}
			if got.Protocol != tt.expected.Protocol {
				t.Errorf("Protocol = %v, want %v", got.Protocol, tt.expected.Protocol)
			}
			if got.Path != tt.expected.Path {
				t.Errorf("Path = %v, want %v", got.Path, tt.expected.Path)
			}
			if got.Parsed != tt.expected.Parsed {
				t.Errorf("Parsed = %v, want %v", got.Parsed, tt.expected.Parsed)
			}
		})
	}
}
