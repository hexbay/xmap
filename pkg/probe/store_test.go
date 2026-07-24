package probe

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// 可视化探针排序，返回格式化的字符串表示
func visualizeProbes(probes []*Probe) string {
	if len(probes) == 0 {
		return "[空探针列表]"
	}

	var sb strings.Builder
	sb.WriteString("探针排序情况:\n")
	sb.WriteString("序号\t名称\t稀有度\t端口\t\tSSL端口\n")
	sb.WriteString("----------------------------------------\n")

	for i, p := range probes {
		ports := fmt.Sprintf("%v", p.Ports)
		sslPorts := fmt.Sprintf("%v", p.SSLPorts)
		sb.WriteString(fmt.Sprintf("%d\t%s\t%d\t%s\t%s\n",
			i+1, p.Name, p.Rarity, ports, sslPorts))
	}

	return sb.String()
}

// 检查指定探针是否在前N个位置中
func checkSorting(probes []*Probe, name string, max int) bool {
	for i := 0; i < len(probes) && i < max; i++ {
		if probes[i].Name == name {
			return true
		}
	}
	return false
}

func TestGetProbeForPort(t *testing.T) {
	store, err := GetStoreWithOptions("", 9, false)
	assert.Nil(t, err)
	testCases := []struct {
		protocol string
		port     int
		ssl      bool
		probe    string
		max      int
	}{
		{
			protocol: "tcp",
			port:     80,
			ssl:      false,
			probe:    "GetRequest",
			max:      1,
		},
		{
			protocol: "tcp",
			port:     22,
			ssl:      false,
			probe:    "NULL",
			max:      1,
		},
	}
	for _, tc := range testCases {
		probes := store.GetProbeForPort(tc.protocol, tc.port, tc.ssl)
		if checkSorting(probes, tc.probe, tc.max) {
			println("Sorted correctly")
		} else {
			println(visualizeProbes(probes))
			t.Fatal("Sorted incorrectly:", probes)

		}
	}
}

func TestSMB2NegotiateIsPreferredForPort445(t *testing.T) {
	store, err := GetStoreWithOptions("", 9, true)
	assert.NoError(t, err)
	probes := store.GetProbeForPort(TCP, 445, false)
	if assert.NotEmpty(t, probes) {
		assert.Equal(t, "SMB2NmapNegotiate", probes[0].Name)
	}
}
